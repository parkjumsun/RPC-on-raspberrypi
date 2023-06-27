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
#include <linux/in.h>  
#include <linux/inet.h>  
#include <linux/socket.h>  
#include <net/sock.h> 
#include <linux/gpio.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include "rpc_raspberry_receiver.h"

#define DEV_NAME "rpc_raspberry_receiver"

MODULE_LICENSE("GPL");

#define BUFFSIZE 100

struct socket* sock = NULL;
struct socket* connection_sock[MAX_CONNECTION] = { NULL };

static dev_t dev_num;
static struct cdev* cd_cdev;

struct kvec* send_vec[MAX_CONNECTION];
struct kvec* recv_vec[MAX_CONNECTION];
struct msghdr* send_msg[MAX_CONNECTION];
struct msghdr* recv_msg[MAX_CONNECTION];
char send_byte_buffer[MAX_CONNECTION][BUFFSIZE];
char recv_byte_buffer[MAX_CONNECTION][BUFFSIZE];
static unsigned long socketIdx = 0;

struct socket* interrupt_sock[MAX_CONNECTION] = { NULL };
struct kvec* interrupt_send_vec[MAX_CONNECTION];
struct kvec* interrupt_recv_vec[MAX_CONNECTION];
struct msghdr* interrupt_send_msg[MAX_CONNECTION];
struct msghdr* interrupt_recv_msg[MAX_CONNECTION];
char interrupt_send_byte_buffer[MAX_CONNECTION][BUFFSIZE];
char interrupt_recv_byte_buffer[MAX_CONNECTION][BUFFSIZE];

int curGroupNum[MAX_GROUP_NUM] = {0};
int gpioToSock[GPIO_MAX][MAX_GROUP_NUM] = {0};
int curGpioNum[GPIO_MAX] = {0};
int gpioBuffer[GPIO_MAX] = {0};
static unsigned long irq_sock_idx = 0;

struct task_struct* main_task[MAX_CONNECTION] = { NULL };

static int groupGPIO[MAX_GROUP_NUM][MAX_GROUP_NUM] = {0};




static struct workqueue_struct *interrupt_wq;

typedef struct {
    struct work_struct interrupt_work;
    char gpio;
}interrupt_work_t;

interrupt_work_t* interrupt_task[GPIO_MAX];

spinlock_t mainsocket_lock;
spinlock_t group_lock;
spinlock_t interrupt_lock;



static int init_socket(unsigned long* arg){
    unsigned long portnum;
    struct sockaddr_in s_addr;
    int ret = 1;
    ret = copy_from_user(&portnum, arg, sizeof(unsigned long));
    s_addr.sin_family=AF_INET;
    s_addr.sin_port=htons(portnum);  
    s_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock); 
    if(ret){  
        printk("rpc_raspberry_receiver: socket_create error!\n");  
        ret = -1;
    }
    else{
        printk("rpc_raspberry_receiver: socket_create ok!\n");
        ret=kernel_bind(sock,(struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));  
        if(ret<0){  
            printk("rpc_raspberry_receiver: bind error\n");  
            ret = -1;
        }
        else{            
            printk("rpc_raspberry_receiver: bind ok!\n");  
            ret=kernel_listen(sock,10);  
            if(ret<0){  
                printk("rpc_raspberry_receiver: listen error\n");  
                ret = -1;  
            }  
            else{
                printk("rpc_raspberry_receiver: listen ok!\n"); 
                ret = 1;
            }    
        }
    }
    return ret;
}

int send_message(unsigned long idx, void* arg, int arg_size){
    int ret;
    send_vec[idx]->iov_base = send_byte_buffer[idx]; 
    send_vec[idx]->iov_len = BUFFSIZE;
    memcpy(send_byte_buffer[idx], arg, arg_size);
    ret = kernel_sendmsg(connection_sock[idx], send_msg[idx], send_vec[idx], 1, arg_size);
    if(ret < 0){
        printk("rpc_raspberry_receiver: send error!!\n");
    }
    else{
        printk("rpc_raspberry_receiver: send ok!!\n");
    }
    return ret;
}

int receive_message(unsigned long idx, int size){
    int ret = 0;
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;
    ret = kernel_recvmsg(connection_sock[idx], recv_msg[idx], recv_vec[idx], 1, size, 0);
    if(ret < 0){
            printk("rpc_raspberry_receiver: receive error!!\n");
    }
    else{
        printk("rpc_raspberry_receiver: reiceive ok!!\n");
    }
    return ret;
}


int run_request_gpio(unsigned long idx){
    char byte_reply;
    struct request_gpio_one_arg_receiver kern_rgo; 
    int ret = 0;
    unsigned long flag;
    printk("rpc_raspberry_receiver: request gpio!!\n");
    ret = receive_message(idx, sizeof(struct request_gpio_one_arg_receiver));
    if(ret >= 0){
        memcpy(&kern_rgo, recv_byte_buffer[idx], sizeof(struct request_gpio_one_arg_receiver));
        if(kern_rgo.flags == 0){
            flag = GPIOF_IN;
        }
        else if(kern_rgo.flags == 1){
            flag = GPIOF_OUT_INIT_LOW;
        }
        else{
            flag = GPIOF_OUT_INIT_HIGH;
        }
        ret = gpio_request_one(kern_rgo.gpio, flag, kern_rgo.label);
        if(ret == 0){
            byte_reply = 1;
        }
        else
            byte_reply = -1;

        ret = send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}

int run_free_gpio(unsigned long idx){
    char byte_reply;
    struct gpio_free_arg_receiver kern_gf; 
    int ret = 0;
    printk("rpc_raspberry_receiver: free gpio!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct gpio_free_arg_receiver));
    if(ret >= 0){
        memcpy(&kern_gf, recv_byte_buffer[idx], sizeof(struct gpio_free_arg_receiver));
        gpio_free(kern_gf.gpio);
        
        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}

int run_gpio_write(unsigned long idx){
    char byte_reply;
    struct gpio_set_value_receiver kern_gsv; 
    int ret = 0;
    printk("rpc_raspberry_receiver: write gpio!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct gpio_set_value_receiver));
    if(ret >= 0){
        memcpy(&kern_gsv, recv_byte_buffer[idx], sizeof(struct gpio_set_value_receiver));
        gpio_set_value(kern_gsv.gpio, kern_gsv.value);
        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}


int run_gpio_read(unsigned long idx){
    int int_reply = 0;
    struct gpio_get_value_receiver kern_ggv; 
    int ret = 0;
    printk("rpc_raspberry_receiver: read gpio!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct gpio_get_value_receiver));
    if(ret >= 0){
        memcpy(&kern_ggv, recv_byte_buffer[idx], sizeof(struct gpio_get_value_receiver));
        int_reply = gpio_get_value(kern_ggv.gpio);
        send_message(idx, &int_reply, sizeof(int));
    }
    return 1;
}

int run_request_multi_gpio(unsigned long idx){
    char byte_reply;
    struct request_multi_gpio_one_arg_receiver kern_rmgo; 
    int ret = 0;
    unsigned long flag;
    printk("rpc_raspberry_receiver: request multi gpio!!\n");
    ret = receive_message(idx, sizeof(struct request_multi_gpio_one_arg_receiver));
    if(ret >= 0){
        memcpy(&kern_rmgo, recv_byte_buffer[idx], sizeof(struct request_multi_gpio_one_arg_receiver));
        if(kern_rmgo.flags == 0){
            flag = GPIOF_IN;
        }
        else if(kern_rmgo.flags == 1){
            flag = GPIOF_OUT_INIT_LOW;
        }
        else{
            flag = GPIOF_OUT_INIT_HIGH;
        }
        spin_lock(&group_lock);
        ret = gpio_request_one(kern_rmgo.gpio, flag, kern_rmgo.label);
        groupGPIO[kern_rmgo.groupIdx][curGroupNum[kern_rmgo.groupIdx]] = kern_rmgo.gpio;
        curGroupNum[kern_rmgo.groupIdx]++;
        spin_unlock(&group_lock);


        if(ret == 0){
            byte_reply = 1;
        }
        else
            byte_reply = -1;

        ret = send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}

int run_free_multi_gpio(unsigned long idx){
    char byte_reply;
    struct multi_gpio_free_arg_receiver kern_mgf; 
    int ret = 0;
    int i = 0;
    int deletedIdx = 0;
    printk("rpc_raspberry_receiver: multi free gpio!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct multi_gpio_free_arg_receiver));
    if(ret >= 0){

        memcpy(&kern_mgf, recv_byte_buffer[idx], sizeof(struct multi_gpio_free_arg_receiver));
        gpio_free(kern_mgf.gpio);


        spin_lock(&group_lock);
        for(i = 0; i < curGroupNum[kern_mgf.groupIdx]; i++){
            if(groupGPIO[kern_mgf.groupIdx][i] == kern_mgf.gpio){
                deletedIdx = i;
                break;
            }
        }
        for(i = deletedIdx; i < curGroupNum[kern_mgf.groupIdx]; i++){
                groupGPIO[kern_mgf.groupIdx][i] = groupGPIO[kern_mgf.groupIdx][i + 1];
        }
        curGroupNum[kern_mgf.groupIdx]--;
        spin_unlock(&group_lock);

        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}

int run_multi_gpio_write(unsigned long idx){
    char byte_reply;
    struct multi_gpio_set_value_receiver kern_mgsv; 
    int ret = 0;
    int i = 0;
    unsigned int groupId;
    printk("rpc_raspberry_receiver: write gpio!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct multi_gpio_set_value_receiver));
    if(ret >= 0){
        memcpy(&kern_mgsv, recv_byte_buffer[idx], sizeof(struct multi_gpio_set_value_receiver));
        groupId = kern_mgsv.groupId;
        for(i = 0; i < curGroupNum[groupId]; i++){
            gpio_set_value(groupGPIO[groupId][i], kern_mgsv.value);
        }
        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
    }
    return 1;
}


int send_interrupt_message(unsigned long idx, void* arg, int arg_size){
    int ret;
    interrupt_send_vec[idx]->iov_base = interrupt_send_byte_buffer[idx]; 
    interrupt_send_vec[idx]->iov_len = BUFFSIZE;
    memcpy(interrupt_send_byte_buffer[idx], arg, arg_size);
    ret = kernel_sendmsg(interrupt_sock[idx], interrupt_send_msg[idx], interrupt_send_vec[idx], 1, arg_size);

    if(ret < 0){
        printk("rpc_raspberry_receiver: interrupt send error!!\n");
        printk("ret: %d", ret);
    }
    else{
        printk("rpc_raspberry_receiver: interrupt send ok!!\n");
    }
    return ret;
}

int receive_interrupt_message(unsigned long idx, int size){
    int ret = 0;
    interrupt_recv_vec[idx]->iov_base = interrupt_recv_byte_buffer[idx]; 
    interrupt_recv_vec[idx]->iov_len = BUFFSIZE;
    ret = kernel_recvmsg(interrupt_sock[idx], interrupt_recv_msg[idx], interrupt_recv_vec[idx], 1, size, 0);
    if(ret < 0){
            printk("rpc_raspberry_sender: receive error!!\n");
    }
    else{
        printk("rpc_raspberry_sender: reiceive ok!!\n");
    }
    return ret;
}



void send_interrupt_signal(struct work_struct* work){
    interrupt_work_t* interrupt_work = (interrupt_work_t*)work;
    int interrupt_socket_idx;
    char gpio = (char)interrupt_work->gpio;
    int ret = 0;
    int i = 0;

    for(i = 1; i < curGpioNum[(unsigned int)gpio] ; i++){
        interrupt_socket_idx = gpioToSock[(unsigned int)gpio][i];
        ret = send_interrupt_message(interrupt_socket_idx, (void *)&gpio, sizeof(char));
    }
}

static irqreturn_t schedule_tasklet(int irq, void* dev_id){
    int i;
    for(i = 0; i < GPIO_MAX; i++){
        if(irq == gpioToSock[i][0]){
            queue_work(interrupt_wq, (struct work_struct*)interrupt_task[i]);
            break;
        }
    }
    return IRQ_HANDLED;
}

int init_interrupt_socket(unsigned long idx, int portnum, char* ip_addr){
    struct sockaddr_in s_addr;
    int ret;
    memset(&s_addr,0,sizeof(s_addr));  
    s_addr.sin_family=AF_INET;
    s_addr.sin_port=htons(portnum);  
    s_addr.sin_addr.s_addr=in_aton(ip_addr);
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &interrupt_sock[irq_sock_idx]);
    if (ret < 0) {
        printk("rpc_raspberry_receiver: socket create error!\n");
        ret = -1;
    }
    ret = interrupt_sock[irq_sock_idx]->ops->connect(interrupt_sock[irq_sock_idx], (struct sockaddr *)&s_addr, sizeof(s_addr), 0);
    if (ret != 0) {
        printk("rpc_raspberry_receiver: connect error!\n");
        printk("%d\n",ret);
        ret = -1;
    }
    return ret;
}

int run_request_irq(unsigned long idx){
    char byte_reply;
    struct remote_request_irq_receiver kern_riq; 
    int ret;
    int gpio = 0;
    int irq;
    printk("rpc_raspberry_receiver: remote interrupt!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  

    ret = receive_message(idx, sizeof(struct remote_request_irq_receiver));
    if(ret >= 0){
        memcpy(&kern_riq, recv_byte_buffer[idx], sizeof(struct remote_request_irq_receiver));
        gpio = kern_riq.gpio;
        spin_lock(&interrupt_lock);
        //해당 gpio에 처음 request가 들어왔을 때..
        if(curGpioNum[gpio] == 0){
            irq = gpio_to_irq(gpio);
            ret = request_irq(irq, schedule_tasklet, kern_riq.flags, kern_riq.name, NULL);
            if(ret){
                printk("rpc_raspberry_receiver: interrupt fail");
                free_irq(irq, NULL);
            }
            gpioToSock[gpio][0] = irq; //0번은 무조건 irq로
            gpioToSock[gpio][1] = irq_sock_idx; // 1번부터 irq_sock_idx를 하나씩 추가, irq_sock_idx는 interrupt에 연결된 client socket을 구분하는 용도
            curGpioNum[gpio] += 2;
        }
        else{
            gpioToSock[gpio][curGpioNum[gpio]] = irq_sock_idx;
            curGpioNum[gpio]++;
        }
        spin_unlock(&interrupt_lock);
        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
        init_interrupt_socket(irq_sock_idx, kern_riq.port_num, kern_riq.ip_addr);
        irq_sock_idx++;

    }
    return 1;
}


int run_free_irq(unsigned long idx){
    char byte_reply;
    struct remote_free_irq_receiver kern_rfi;
    int ret = 0;
    char gpio = 0;
    signed char endsignal = 0;
    int interrupt_socket_idx;
    int i = 0;
    printk("rpc_raspberry_receiver: free interrupt!!\n");
    recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
    recv_vec[idx]->iov_len = BUFFSIZE;  
    ret = receive_message(idx, sizeof(struct remote_free_irq_receiver));
    if(ret >= 0){
        memcpy(&kern_rfi, recv_byte_buffer[idx], sizeof(struct remote_free_irq_receiver));
        gpio = (char)kern_rfi.gpio;
        byte_reply = 1;
        send_message(idx, &byte_reply, sizeof(char));
        for(i = 1; i < curGpioNum[(unsigned int)gpio] ; i++){
            endsignal = (-gpio);
            interrupt_socket_idx = gpioToSock[(unsigned int)gpio][i];
            ret = send_interrupt_message(interrupt_socket_idx, (void *)&endsignal, sizeof(char));
        }
    }



    return 1;
}


void disconnect_socket(void){
    int i = 0;
    printk("socket disconnect");
    if(sock != NULL){
        printk("sock release!!");
        sock_release(sock);
    }
    for(i = 0; i < MAX_CONNECTION; i++){
        if(connection_sock[i] != NULL){
            sock_release(connection_sock[i]);
        }
    }
}

int mainHandler(void* arg){
    int ret;                
    char byte_reply;
    unsigned long idx = (unsigned long)arg;
    while(true){
        recv_vec[idx]->iov_base = recv_byte_buffer[idx]; 
        recv_vec[idx]->iov_len = BUFFSIZE;  
        ret = receive_message(idx, sizeof(char));
        if(ret >= 0){
            printk("rpc_raspberry_receiver: receiev value %d", recv_byte_buffer[idx][0]);
            byte_reply = 1;
            send_message(idx, &byte_reply, sizeof(char));
            if(recv_byte_buffer[idx][0] == GPIO_REQUEST_ONE){
                run_request_gpio(idx);
            }
            else if(recv_byte_buffer[idx][0] == GPIO_REQUEST_WRITE){
                run_gpio_write(idx);
            }
            else if(recv_byte_buffer[idx][0] == GPIO_REQUEST_READ){
                run_gpio_read(idx);
            }
            else if(recv_byte_buffer[idx][0] == GPIO_REQUEST_FREE){
                run_free_gpio(idx);
            }
            else if(recv_byte_buffer[idx][0] == MULTI_GPIO_REQUEST_ONE){
                run_request_multi_gpio(idx);
            }
            else if(recv_byte_buffer[idx][0] == MULTI_GPIO_REQUEST_WRITE){
                run_multi_gpio_write(idx);
            }
            else if(recv_byte_buffer[idx][0] == MULTI_GPIO_REQUEST_FREE){
                run_free_multi_gpio(idx);
            }
            else if(recv_byte_buffer[idx][0] == INTERRUPT_REQUEST){
                run_request_irq(idx);
            }
            else if(recv_byte_buffer[idx][0] == INTERRUPT_FREE){
                run_free_irq(idx);
            }
            else if(recv_byte_buffer[idx][0] == 32){
                printk("error!!\n");
            }
            else if(recv_byte_buffer[idx][0] == END_SIGNAL){
                break;
            }
        }
    }
    return ret;
}



static int wait_connection(void){
    int ret;
    //need to implement synchronization,multiplexing IO
    if(socketIdx < MAX_CONNECTION){
        ret=kernel_accept(sock, &connection_sock[socketIdx], 10);
        if(ret<0){  
            printk("rpc_raspberry_receiver: accept error!\n");  
            ret = -1;
        }
        else{
            printk("rpc_raspberry_receiver: accept ok!\n");
            ret = 1;
            spin_lock(&mainsocket_lock);
            main_task[socketIdx] = kthread_run(mainHandler, (void *)socketIdx, "maintask");   
            socketIdx++;
            spin_unlock(&mainsocket_lock);
        }
    }
    return ret;
}

static int rpc_raspberry_receiver_open(struct inode* inode, struct file* file){
    printk("rpc_raspberry_receiver: open\n");
    return 0;
}

static int rpc_raspberry_receiver_release(struct inode* inode, struct file* file){
    printk("rpc_raspberry_receiver: release\n");
    return 0;
}

static long rpc_raspberry_receiver_ioctl(struct file* file, unsigned int cmd, unsigned long arg){
    int ret = 0;
    unsigned long* port_arg;
    printk("rpc_raspberry_receiver: IOCTL\n");
    switch(cmd){
        case INIT:
            port_arg = (unsigned long*)arg;
            init_socket(port_arg);
            break;
        case WAIT_CONNECTION:
            wait_connection();
            break;
    }
    return ret;
}


struct file_operations rpc_raspberry_receiver_ops = {
    .open = rpc_raspberry_receiver_open,
    .release = rpc_raspberry_receiver_release,
    .unlocked_ioctl = rpc_raspberry_receiver_ioctl
};

static int __init rpc_raspberry_receiver_init(void){
    int i = 0;
    printk("rpc_raspberry_receiver: Init Module\n");
    alloc_chrdev_region(&dev_num, 0, 1, DEV_NAME);
    cd_cdev = cdev_alloc();
    cdev_init(cd_cdev, &rpc_raspberry_receiver_ops);
    cdev_add(cd_cdev, dev_num, 1);
    spin_lock_init(&mainsocket_lock);
    spin_lock_init(&group_lock);
    spin_lock_init(&interrupt_lock);

    for(i = 0; i < MAX_CONNECTION; i++){
        send_vec[i] = kmalloc(sizeof(struct kvec), GFP_KERNEL);
        recv_vec[i] = kmalloc(sizeof(struct kvec), GFP_KERNEL);
        send_msg[i] = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
        recv_msg[i] = kmalloc(sizeof(struct msghdr), GFP_KERNEL);
        memset(send_vec[i], 0, sizeof(struct kvec));
        memset(recv_vec[i], 0, sizeof(struct kvec));
        memset(send_msg[i], 0, sizeof(struct msghdr));
        memset(recv_msg[i], 0, sizeof(struct msghdr));
        memset(send_byte_buffer[i], 0, BUFFSIZE);
        memset(recv_byte_buffer[i], 0, BUFFSIZE);
        recv_msg[i]->msg_flags = MSG_NOSIGNAL;    
    }

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

    interrupt_wq = create_workqueue("interrupt_workqueue");
    
    for(i = 0; i < GPIO_MAX; i++){
        interrupt_task[i] = (interrupt_work_t*)kmalloc(sizeof(interrupt_work_t), GFP_KERNEL);
        interrupt_task[i]->gpio = i;    
        INIT_WORK((struct work_struct*)&(interrupt_task[i]->interrupt_work), send_interrupt_signal);
    }


    return 0;
}

static void __exit rpc_raspberry_receiver_exit(void){
    int i;
    printk("rpc_raspberry_receiver: Exit Module\n");
    if(sock != NULL){
        sock_release(sock);
    }
    for(i = 0; i < MAX_CONNECTION; i++){
        if(connection_sock[i] != NULL){
            sock_release(connection_sock[i]);
        }
        if(interrupt_sock[i] != NULL)
            sock_release(interrupt_sock[i]);
    }


    
    for(i = 0; i < GPIO_MAX; i++){
        kfree(interrupt_task[i]);
        if(gpioToSock[i][0] != 0)
            free_irq(gpioToSock[i][0], NULL);

    }
    flush_workqueue(interrupt_wq);
    destroy_workqueue(interrupt_wq);

    cdev_del(cd_cdev);
    unregister_chrdev_region(dev_num, 1);
    for(i = 0; i < MAX_CONNECTION; i++){
        kfree(send_vec[i]);
        kfree(recv_vec[i]);
        kfree(send_msg[i]);
        kfree(recv_msg[i]);
        kfree(interrupt_send_vec[i]);
        kfree(interrupt_recv_vec[i]);
        kfree(interrupt_send_msg[i]);
        kfree(interrupt_recv_msg[i]);
    }
}



module_init(rpc_raspberry_receiver_init);
module_exit(rpc_raspberry_receiver_exit);






