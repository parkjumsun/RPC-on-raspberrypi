#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/vmalloc.h> 
#include <linux/inet.h>  
#include <linux/gpio.h>
#include <linux/socket.h>  
#include <net/sock.h>  
#include <linux/in.h>  
#include <linux/wait.h>
#include <linux/kthread.h>
#include "rpc_raspberry_sender.h"


#define DEV_NAME "rpc_raspberry_sender"

MODULE_LICENSE("GPL");

#define BUFFSIZE 100


static dev_t dev_num;
static struct cdev* cd_cdev;
struct socket* sock[MAX_CONNECTION] = {NULL};

struct socket* interrupt_sock = NULL; 
struct socket* interrupt_connection_sock[MAX_CONNECTION] = {NULL}; 

struct task_struct* interrupt_receiver[MAX_CONNECTION] = { NULL }; 

unsigned long interrupt_idx = 0;


static int socketIdx = 0;
struct socket_args* kern_sock_arg;
struct kvec* send_vec;
struct kvec* recv_vec;
struct msghdr* send_msg;
struct msghdr* recv_msg;
char send_byte_buffer[BUFFSIZE];
char recv_byte_buffer[BUFFSIZE];


struct kvec* interrupt_send_vec[MAX_CONNECTION];
struct kvec* interrupt_recv_vec[MAX_CONNECTION];
struct msghdr* interrupt_send_msg[MAX_CONNECTION];
struct msghdr* interrupt_recv_msg[MAX_CONNECTION];
char interrupt_send_byte_buffer[MAX_CONNECTION][BUFFSIZE];
char interrupt_recv_byte_buffer[MAX_CONNECTION][BUFFSIZE];


int groupSockIdx[MAX_GROUP_NUM][MAX_GROUP_NUM] = {0};
int curGroupNum[MAX_GROUP_NUM] = {0};

spinlock_t mainsocket_lock;
spinlock_t group_lock;
spinlock_t interrupt_lock;

wait_queue_head_t interrupt_wq;
int gpioSignal[GPIO_MAX] = {0};


static int connect_to_rasp(struct socket_args* arg){
    struct socket_args temp_buf_socket;
    struct sockaddr_in s_addr;
    int ret;

    if(socketIdx >= MAX_CONNECTION){
        return -1;
    }
    ret = copy_from_user(&temp_buf_socket, arg, sizeof(struct socket_args));
    memset(&s_addr,0,sizeof(s_addr));
    spin_lock(&mainsocket_lock);  
    s_addr.sin_family=AF_INET;
    s_addr.sin_port=htons(temp_buf_socket.port_num);  
    s_addr.sin_addr.s_addr=in_aton(temp_buf_socket.ip_addr);
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock[socketIdx]);
    if (ret < 0) {
        printk("rpc_raspberry_sender: socket create error!\n");
        ret = -1;
    }
    else{
        printk("rpc_raspberry_sender: socket create ok!\n");
        ret = sock[socketIdx]->ops->connect(sock[socketIdx], (struct sockaddr *)&s_addr, sizeof(s_addr), 0);
        if (ret != 0) {
            printk("rpc_raspberry_sender: connect error!\n");
            ret = -1;
        }
        else{
            printk("rpc_raspberry_sender: connect ok!\n");
            ret = socketIdx;
            socketIdx++;
        }
    }
    spin_unlock(&mainsocket_lock);

    return ret;
}

int send_message(unsigned long idx, void* arg, int arg_size){
    int ret;
    send_vec->iov_base = send_byte_buffer; 
    send_vec->iov_len = BUFFSIZE;
    memcpy(send_byte_buffer, arg, arg_size);
    ret = kernel_sendmsg(sock[idx], send_msg, send_vec, 1, arg_size);
    if(ret < 0){
        printk("rpc_raspberry_sender: send error!!\n");
    }
    else{
        printk("rpc_raspberry_sender: send ok!!\n");
    }
    return ret;
}

int receive_message(unsigned long idx, int size){
    int ret = 0;
    recv_vec->iov_base = recv_byte_buffer; 
    recv_vec->iov_len = BUFFSIZE;
    ret = kernel_recvmsg(sock[idx], recv_msg, recv_vec, 1, size, 0);
    if(ret < 0){
            printk("rpc_raspberry_sender: receive error!!\n");
    }
    else{
        printk("rpc_raspberry_sender: reiceive ok!!\n");
    }
    return ret;
}

int send_interrupt_message(unsigned long idx, void* arg, int arg_size){
    int ret;
    interrupt_send_vec[idx]->iov_base = interrupt_send_byte_buffer[idx]; 
    interrupt_send_vec[idx]->iov_len = BUFFSIZE;
    memcpy(interrupt_send_byte_buffer[idx], arg, arg_size);
    ret = kernel_sendmsg(interrupt_connection_sock[idx], interrupt_send_msg[idx], interrupt_send_vec[idx], 1, arg_size);
    if(ret < 0){
        printk("rpc_raspberry_sender: send error!!\n");
    }
    else{
        printk("rpc_raspberry_sender: send ok!!\n");
    }
    return ret;
}

int receive_interrupt_message(unsigned long idx, int size){
    int ret = 0;
    interrupt_recv_vec[idx]->iov_base = interrupt_recv_byte_buffer[idx]; 
    interrupt_recv_vec[idx]->iov_len = BUFFSIZE;
    ret = kernel_recvmsg(interrupt_connection_sock[idx], interrupt_recv_msg[idx], interrupt_recv_vec[idx], 1, size, 0);
    if(ret < 0){
            printk("rpc_raspberry_sender: receive error!!\n");
    }
    else{
        printk("rpc_raspberry_sender: reiceive ok!!\n");
    }
    return ret;
}




static int disconnect_to_rasp(unsigned long* arg){
    int kern_service_idx;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_service_idx, arg, sizeof(int));
    byte_request = END_SIGNAL;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            printk("rpc_raspberry_sender: %d\n", recv_byte_buffer[0]);
            ret = recv_byte_buffer[0];
        }
    }
    return ret;
}



static int remote_request_gpio(struct request_gpio_one_arg_sender* arg){
    int kern_service_idx;
    struct request_gpio_one_arg_sender kern_rgo;
    int arg_size = sizeof(struct request_gpio_one_arg_sender);
    void* kern_rgo_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_rgo, arg, arg_size);
    kern_service_idx = kern_rgo.service_num;
    byte_request = GPIO_REQUEST_ONE;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_rgo_address = (void*)&kern_rgo;
            kern_rgo_address += sizeof(kern_rgo.service_num);
            arg_size -= sizeof(kern_rgo.service_num);
            memcpy(send_byte_buffer, kern_rgo_address, arg_size);
            ret = send_message(kern_service_idx, kern_rgo_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}

static int remote_gpio_free(struct gpio_free_arg_sender* arg){
    int kern_service_idx;
    struct gpio_free_arg_sender kern_gf;
    int arg_size = sizeof(struct gpio_free_arg_sender);
    void* kern_gf_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_gf, arg, arg_size);
    kern_service_idx = kern_gf.service_num;
    byte_request = GPIO_REQUEST_FREE;
    ret = send_message(kern_service_idx, &byte_request,sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_gf_address = (void*)&kern_gf;
            kern_gf_address += sizeof(kern_gf.service_num);
            arg_size -= sizeof(kern_gf.service_num);
            memcpy(send_byte_buffer, kern_gf_address, arg_size);
            ret = send_message(kern_service_idx, kern_gf_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}

static int remote_gpio_write(struct gpio_set_value_sender* arg){
    int kern_service_idx;
    struct gpio_set_value_sender kern_gsv;
    int arg_size = sizeof(struct gpio_set_value_sender);
    void* kern_gsv_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_gsv, arg, arg_size);
    kern_service_idx = kern_gsv.service_num;
    byte_request = GPIO_REQUEST_WRITE;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_gsv_address = (void*)&kern_gsv;
            kern_gsv_address += sizeof(kern_gsv.service_num);
            arg_size -= sizeof(kern_gsv.service_num);
            memcpy(send_byte_buffer, kern_gsv_address, arg_size);
            ret = send_message(kern_service_idx, kern_gsv_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}


static int remote_gpio_read(struct gpio_get_value_sender* arg){
    int kern_service_idx;
    struct gpio_get_value_sender kern_ggv;
    int arg_size = sizeof(struct gpio_get_value_sender);
    void* kern_ggv_address;
    int ret;
    char byte_request;
    int* readVal;
    ret = copy_from_user(&kern_ggv, arg, arg_size);
    kern_service_idx = kern_ggv.service_num;
    byte_request = GPIO_REQUEST_READ;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_ggv_address = (void*)&kern_ggv;
            kern_ggv_address += sizeof(kern_ggv.service_num);
            arg_size -= sizeof(kern_ggv.service_num);
            memcpy(send_byte_buffer, kern_ggv_address, arg_size);
            ret = send_message(kern_service_idx, kern_ggv_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(int));
                readVal = (int *)recv_byte_buffer;
            }
        }
    }
    return *readVal;
}


static int multi_remote_request_gpio(struct request_multi_gpio_one_arg_sender* arg){
    int kern_service_idx;
    struct request_multi_gpio_one_arg_sender kern_rmgo;
    int arg_size = sizeof(struct request_multi_gpio_one_arg_sender);
    void* kern_rmgo_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_rmgo, arg, arg_size);
    kern_service_idx = kern_rmgo.service_num;
    byte_request = MULTI_GPIO_REQUEST_ONE;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            spin_lock(&group_lock);
            groupSockIdx[kern_rmgo.groupIdx][curGroupNum[kern_rmgo.groupIdx]] = kern_service_idx;
            curGroupNum[kern_rmgo.groupIdx]++;
            spin_unlock(&group_lock);
            kern_rmgo_address = (void*)&kern_rmgo;
            kern_rmgo_address += sizeof(kern_rmgo.service_num);
            arg_size -= sizeof(kern_rmgo.service_num);
            memcpy(send_byte_buffer, kern_rmgo_address, arg_size);
            ret = send_message(kern_service_idx, kern_rmgo_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}

static int multi_remote_gpio_free(struct multi_gpio_free_arg_sender* arg){
    int kern_service_idx;
    struct multi_gpio_free_arg_sender kern_mgf;
    int arg_size = sizeof(struct multi_gpio_free_arg_sender);
    void* kern_mgf_address;
    int ret;
    char byte_request;
    int i = 0;
    int deletedIdx = 0;
    ret = copy_from_user(&kern_mgf, arg, arg_size);
    kern_service_idx = kern_mgf.service_num;
    byte_request = MULTI_GPIO_REQUEST_FREE;
    ret = send_message(kern_service_idx, &byte_request,sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        spin_lock(&group_lock);
        if(ret >= 0){
            for(i = 0; i < curGroupNum[kern_mgf.groupIdx]; i++){
                if(groupSockIdx[kern_mgf.groupIdx][i] == kern_service_idx){
                    deletedIdx = i;
                    break;
                }
            }
            for(i = deletedIdx; i < curGroupNum[kern_mgf.groupIdx]; i++){
                groupSockIdx[kern_mgf.groupIdx][i] = groupSockIdx[kern_mgf.groupIdx][i + 1];
            }
            curGroupNum[kern_mgf.groupIdx]--;
        spin_unlock(&group_lock);

            kern_mgf_address = (void*)&kern_mgf;
            kern_mgf_address += sizeof(kern_mgf.service_num);
            arg_size -= sizeof(kern_mgf.service_num);
            memcpy(send_byte_buffer, kern_mgf_address, arg_size);
            ret = send_message(kern_service_idx, kern_mgf_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}

static int multi_remote_gpio_write(struct multi_gpio_set_value_sender* arg){
    int kern_service_idx;
    struct multi_gpio_set_value_sender kern_mgsv;
    int arg_size = sizeof(struct multi_gpio_set_value_sender);
    void* kern_mgsv_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_mgsv, arg, arg_size);
    kern_service_idx = kern_mgsv.service_num;
    byte_request = MULTI_GPIO_REQUEST_WRITE;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_mgsv_address = (void*)&kern_mgsv;
            kern_mgsv_address += sizeof(kern_mgsv.service_num);
            arg_size -= sizeof(kern_mgsv.service_num);
            memcpy(send_byte_buffer, kern_mgsv_address, arg_size);
            ret = send_message(kern_service_idx, kern_mgsv_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}


int receive_interrupt(void* arg){
    unsigned long idx = (unsigned long)arg;
    int ret;
    signed char gpio;

    ret=kernel_accept(interrupt_sock, &interrupt_connection_sock[idx], 10);
    if(ret<0){  
        printk("rpc_raspberry_sender: accept error!\n");  
        ret = -1;
    }
    else{
        printk("rpc_raspberry_sender: accept ok!\n");
        while(1){
            ret = receive_interrupt_message(idx, sizeof(char));
            gpio = *((char*)interrupt_recv_byte_buffer[idx]);
            printk("interrupt receive: %d\n", gpio);
            if(gpio < 0){
                gpio = (-gpio);
                gpioSignal[(unsigned int)gpio] = -gpio;
            }
            else
                gpioSignal[(unsigned int)gpio] = gpio;

            wake_up_interruptible(&interrupt_wq);
            if(gpioSignal[(unsigned int)gpio] < 0)
                break;  
        }
    }
    return ret;
}

static int init_interrupt_socket(int portnum){
    struct sockaddr_in s_addr;
    int ret;
    s_addr.sin_family=AF_INET;
    s_addr.sin_port=htons(portnum);  
    s_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &interrupt_sock); 
    if(ret){  
        printk("rpc_raspberry_sender: socket_create error!\n");  
        ret = -1;
    }
    else{
        printk("rpc_raspberry_sender: socket_create ok!\n");
        ret=kernel_bind(interrupt_sock,(struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));  
        if(ret<0){  
            printk("rpc_raspberry_sender: bind error\n");  
            ret = -1;
        }
        else{            
            printk("rpc_raspberry_sender: bind ok!\n");  
            ret=kernel_listen(interrupt_sock,10);  
            if(ret<0){  
                printk("rpc_raspberry_sender: listen error\n");  
                ret = -1;  
            }  
            else{
                printk("rpc_raspberry_sender: listen ok!\n"); 
                ret = 1;
            }    
        }
    }
    return ret;
}

static int remote_interrupt_request(struct remote_request_irq_sender* arg){
    int kern_service_idx;
    struct remote_request_irq_sender kern_riq;
    int arg_size = sizeof(struct remote_request_irq_sender);
    void* kern_riq_address;
    int ret;
    char byte_request;
    ret = copy_from_user(&kern_riq, arg, arg_size);
    kern_service_idx = kern_riq.service_num;
    byte_request = INTERRUPT_REQUEST;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            spin_lock(&interrupt_lock);
            //처음 interrupt를 보낼 때..
            if(interrupt_idx == 0)
                init_interrupt_socket(kern_riq.port_num);
            interrupt_receiver[interrupt_idx] = kthread_run(receive_interrupt, (void *)interrupt_idx, kern_riq.name);
            interrupt_idx++;
            kern_riq_address = (void*)&kern_riq;
            kern_riq_address += sizeof(kern_riq.service_num);
            arg_size -= sizeof(kern_riq.service_num);
            spin_unlock(&interrupt_lock);
            memcpy(send_byte_buffer, kern_riq_address, arg_size);
            ret = send_message(kern_service_idx, kern_riq_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}

static int wait_interrupt(int* arg){
    int kern_gpio;
    int ret = 1;
    ret = copy_from_user(&kern_gpio, arg, sizeof(int));
    gpioSignal[kern_gpio] = 0;
    wait_event_interruptible(interrupt_wq, gpioSignal[kern_gpio] == kern_gpio || gpioSignal[kern_gpio] == (-kern_gpio));
    if(gpioSignal[kern_gpio]  < 0)
        ret = -1;
    return ret;
}


static int local_request_gpio(struct local_request_gpio_one_arg_sender* arg){
    struct local_request_gpio_one_arg_sender kern_lrgo;
    unsigned long flag;
    int ret;
    ret = copy_from_user(&kern_lrgo, arg, sizeof(struct local_request_gpio_one_arg_sender));
    if(kern_lrgo.flags == 0){
        flag = GPIOF_IN;
    }
    else if(kern_lrgo.flags == 1){
        flag = GPIOF_OUT_INIT_LOW;
    }
    else{
        flag = GPIOF_OUT_INIT_HIGH;
    }
    ret = gpio_request_one(kern_lrgo.gpio, flag, kern_lrgo.label);
    return ret;
}

static int local_gpio_free(struct local_gpio_free_arg_sender* arg){
    struct local_gpio_free_arg_sender kern_lgf;
    int ret;
    ret = copy_from_user(&kern_lgf, arg, sizeof(struct local_gpio_free_arg_sender));
    gpio_free(kern_lgf.gpio);
    return 1;
}

static int local_gpio_write(struct local_gpio_set_value_sender* arg){
    struct local_gpio_set_value_sender kern_lgsv;
    int ret;
    ret = copy_from_user(&kern_lgsv, arg, sizeof(struct local_gpio_set_value_sender));
    gpio_set_value(kern_lgsv.gpio, kern_lgsv.value);
    return 1;
}

static int local_gpio_read(struct local_gpio_get_value_sender* arg){
    int ret;
    struct local_gpio_get_value_sender kern_lggv;
    ret = copy_from_user(&kern_lggv, arg, sizeof(struct local_gpio_get_value_sender));
    ret = gpio_get_value(kern_lggv.gpio);
    return ret;
}

static int remote_interrupt_free(struct remote_free_irq_sender* arg){
    int kern_service_idx;
    struct remote_free_irq_sender kern_rfis;
    int arg_size = sizeof(struct remote_free_irq_sender);
    void* kern_rfis_address;
    int ret;
    signed char byte_request;
    ret = copy_from_user(&kern_rfis, arg, arg_size);
    kern_service_idx = kern_rfis.service_num;
    byte_request = INTERRUPT_FREE;
    ret = send_message(kern_service_idx, &byte_request, sizeof(char));
    if(ret >= 0){
        ret = receive_message(kern_service_idx, sizeof(char));
        if(ret >= 0){
            kern_rfis_address = (void*)&kern_rfis;
            kern_rfis_address += sizeof(kern_rfis.service_num);
            arg_size -= sizeof(kern_rfis.service_num);
            memcpy(send_byte_buffer, kern_rfis_address, arg_size);
            ret = send_message(kern_service_idx, kern_rfis_address, arg_size);
            if(ret >= 0){
                ret = receive_message(kern_service_idx, sizeof(char));
            }
        }
    }
    return ret;
}




static int rpc_raspberry_sender_open(struct inode* inode, struct file* file){
    printk("rpc_raspberry_sender: open\n");
    return 0;
}

static int rpc_raspberry_sender_release(struct inode* inode, struct file* file){
    printk("rpc_raspberry_sender: release\n");
    return 0;
}

static long rpc_raspberry_sender_ioctl(struct file* file, unsigned int cmd, unsigned long arg){
    int ret = 0;
    struct socket_args* s_arg;
    struct request_gpio_one_arg_sender* rgo_arg;
    struct gpio_free_arg_sender* gf_arg;
    struct gpio_set_value_sender* gsv_arg;
    struct gpio_get_value_sender* ggv_arg;
    struct request_multi_gpio_one_arg_sender* rmgo_arg;
    struct multi_gpio_free_arg_sender* mgf_arg;
    struct multi_gpio_set_value_sender* mgsv_arg;
    struct remote_request_irq_sender* riq_arg;
    struct local_request_gpio_one_arg_sender* lrgo_arg;
    struct local_gpio_set_value_sender* lgsv_arg;
    struct local_gpio_free_arg_sender* lgf_arg;
    struct local_gpio_get_value_sender* lggv_arg;
    struct remote_free_irq_sender* rfis_arg;
    unsigned long* service_idx;
    int* gpio_arg; 
    

    printk("rpc_raspberry_sender: IOCTL\n");
    switch(cmd){
        case CONNECT_TO_RASP:
            s_arg = (struct socket_args*)arg;
            ret = connect_to_rasp(s_arg);
            break;
        case DISCONNECT_TO_RASP:
            service_idx = (unsigned long*)arg;
            ret = disconnect_to_rasp(service_idx);
            break;
        case REMOTE_GPIO_REQUEST:
            rgo_arg = (struct request_gpio_one_arg_sender*)arg;
            ret = remote_request_gpio(rgo_arg);
            break;

        case REMOTE_GPIO_WRITE:
            gsv_arg = (struct gpio_set_value_sender*)arg;
            ret = remote_gpio_write(gsv_arg);
            break;

        case REMOTE_GPIO_READ:
            ggv_arg = (struct gpio_get_value_sender*)arg;
            ret = remote_gpio_read(ggv_arg);
            break;

        case REMOTE_GPIO_FREE:
            gf_arg = (struct gpio_free_arg_sender*)arg;
            ret = remote_gpio_free(gf_arg);
            break;

        case REMOTE_MULTI_GPIO_REQUEST:
            rmgo_arg = (struct request_multi_gpio_one_arg_sender*)arg;
            ret = multi_remote_request_gpio(rmgo_arg);
            break;

        case REMOTE_GPIO_MULTI_WRITE:
            mgsv_arg = (struct multi_gpio_set_value_sender*)arg;
            ret = multi_remote_gpio_write(mgsv_arg);
            break;

        case REMOTE_GPIO_MULTI_FREE:
            mgf_arg = (struct multi_gpio_free_arg_sender*)arg;
            ret = multi_remote_gpio_free(mgf_arg);
            break;    

        case REMOTE_INTERRUPT_REQUEST:
            riq_arg = (struct remote_request_irq_sender*)arg;
            ret = remote_interrupt_request(riq_arg);
            break;
        
        case WAIT_INTERRUPT_SIGNAL:
            gpio_arg = (int*)arg;
            ret = wait_interrupt(gpio_arg);
            break;

        case LOCAL_GPIO_REQUEST:
            lrgo_arg = (struct local_request_gpio_one_arg_sender *)arg;
            ret = local_request_gpio(lrgo_arg);
            break;

        case LOCAL_GPIO_FREE:
            lgf_arg = (struct local_gpio_free_arg_sender *)arg;
            ret = local_gpio_free(lgf_arg);
            break; 

        case LOCAL_GPIO_WRITE:
            lgsv_arg = (struct local_gpio_set_value_sender*)arg;
            ret = local_gpio_write(lgsv_arg);
            break;

        case LOCAL_GPIO_READ:
            lggv_arg = (struct local_gpio_get_value_sender*)arg;
            ret = local_gpio_read(lggv_arg);
            break;
        
        case REMOTE_FREE_IRQ:
            rfis_arg = (struct remote_free_irq_sender*)arg;
            ret = remote_interrupt_free(rfis_arg);
            break;

    }
    return ret;
}


struct file_operations rpc_raspberry_sender_ops = {
    .open = rpc_raspberry_sender_open,
    .release = rpc_raspberry_sender_release,
    .unlocked_ioctl = rpc_raspberry_sender_ioctl
};

static int __init rpc_raspberry_sender_init(void){
    int i;
    printk("rpc_raspberry_sender: Init Module\n");
    alloc_chrdev_region(&dev_num, 0, 1, DEV_NAME);
    cd_cdev = cdev_alloc();
    cdev_init(cd_cdev, &rpc_raspberry_sender_ops);
    cdev_add(cd_cdev, dev_num, 1);
    init_waitqueue_head(&interrupt_wq);
    spin_lock_init(&mainsocket_lock);
    spin_lock_init(&group_lock);
    spin_lock_init(&interrupt_lock);


    send_vec = kmalloc(sizeof(struct kvec), GFP_KERNEL);
    recv_vec = kmalloc(sizeof(struct kvec), GFP_KERNEL);
    send_msg = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
    recv_msg = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
    memset(send_vec, 0, sizeof(struct kvec));
    memset(recv_vec, 0, sizeof(struct kvec));
    memset(send_msg, 0, sizeof(struct msghdr));
    memset(recv_msg, 0, sizeof(struct msghdr));
    memset(send_byte_buffer, 0, BUFFSIZE);
    memset(recv_byte_buffer, 0, BUFFSIZE);
    recv_msg->msg_flags = MSG_NOSIGNAL;    


   for(i = 0; i < MAX_CONNECTION; i++){
        interrupt_send_vec[i] = kmalloc(sizeof(struct kvec), GFP_KERNEL);
        interrupt_recv_vec[i] = kmalloc(sizeof(struct kvec), GFP_KERNEL);
        interrupt_send_msg[i] = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
        interrupt_recv_msg[i] = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
        memset(interrupt_send_vec[i], 0, sizeof(struct kvec));
        memset(interrupt_recv_vec[i], 0, sizeof(struct kvec));
        memset(interrupt_send_msg[i], 0, sizeof(struct msghdr));
        memset(interrupt_recv_msg[i], 0, sizeof(struct msghdr));
        memset(interrupt_send_byte_buffer[i], 0, BUFFSIZE);
        memset(interrupt_recv_byte_buffer[i], 0, BUFFSIZE);
        interrupt_recv_msg[i]->msg_flags = MSG_NOSIGNAL;    
    }
    

    return 0;
}

static void __exit rpc_raspberry_sender_exit(void){
    int i = 0;
    printk("rpc_raspberry_sender: Exit Module\n");
    cdev_del(cd_cdev);
    unregister_chrdev_region(dev_num, 1);
    for(i = 0; i < MAX_CONNECTION; i++){
        if(sock[i] != NULL){
            sock_release(sock[i]);
        }
    }

    if(interrupt_sock != NULL){
        sock_release(interrupt_sock);
    }
    
    for(i = 0; i < MAX_CONNECTION; i++){
        if(interrupt_connection_sock[i] != NULL){
            sock_release(interrupt_connection_sock[i]);
        }
    }

    kfree(send_vec);
    kfree(recv_vec);
    kfree(send_msg);
    kfree(recv_msg);
    for(i = 0; i < MAX_CONNECTION; i++){
        kfree(interrupt_send_vec[i]);
        kfree(interrupt_recv_vec[i]);
        kfree(interrupt_send_msg[i]);
        kfree(interrupt_recv_msg[i]);
    }
}

module_init(rpc_raspberry_sender_init);
module_exit(rpc_raspberry_sender_exit);






