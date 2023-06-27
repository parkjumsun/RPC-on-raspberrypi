#include "rpc_raspberry_sender.h"
#include <string.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

#define REMOTE_GPIOF_IN 0
#define REMOTE_GPIOF_INIT_LOW 1
#define REOMOTE_GPIOF_INIT_HIGH 2

typedef struct {
    void (*function)(int);
    unsigned int gpio;
    int service_num;
} thread_arg_t;

int service_to_fd[MAX_CONNECTION];
pthread_t thread[10];
int thread_idx = 0;

int thread_exit_flag = 0;

int connect_to_rasp(char* ip_addr, int port_num){
    int fd = open("/dev/rpc_raspberry_sender", O_RDWR);
    if(fd < 0)
        return -1;
    struct socket_args socket_args_lib;
    strcpy(socket_args_lib.ip_addr, ip_addr);
    socket_args_lib.port_num = port_num;
    int service_num = ioctl(fd, CONNECT_TO_RASP, &socket_args_lib);
    service_to_fd[service_num] = fd;
    return service_num;
}




int disconnect_to_rasp(int service_num){
    thread_exit_flag = 1;
    return ioctl(service_to_fd[service_num], DISCONNECT_TO_RASP, &service_num);
}

int remote_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label){
    struct request_gpio_one_arg_sender rgo;
    rgo.service_num = service_num;
    strcpy(rgo.label, label);
    rgo.gpio = gpio;
    rgo.flags = flags;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_REQUEST, &rgo);
}

int remote_gpio_free(int service_num, unsigned int gpio){
    struct gpio_free_arg_sender gf;
    gf.gpio = gpio;
    gf.service_num = service_num;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_FREE, &gf);
}

int remote_gpio_set_value(int service_num, unsigned int gpio, int value){
    struct gpio_set_value_sender gsv;
    gsv.gpio = gpio;
    gsv.service_num = service_num;
    gsv.value = value;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_WRITE, &gsv);
}

int remote_gpio_get_value(int service_num, unsigned int gpio){
    struct gpio_get_value_sender ggv;
    ggv.gpio = gpio;
    ggv.service_num = service_num;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_READ, &ggv);
}

int remote_multi_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label, int groudId){
    struct request_multi_gpio_one_arg_sender rmgo;
    rmgo.service_num = service_num;
    strcpy(rmgo.label, label);
    rmgo.gpio = gpio;
    rmgo.flags = flags;
    rmgo.groupIdx = groudId;
    return ioctl(service_to_fd[service_num], REMOTE_MULTI_GPIO_REQUEST, &rmgo);
}

int remote_multi_gpio_free(int service_num, unsigned int gpio, int groudId){
    struct multi_gpio_free_arg_sender mgf;
    mgf.service_num = service_num;
    mgf.gpio = gpio;
    mgf.groupIdx = groudId;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_MULTI_FREE, &mgf);
}

int remote_multi_gpio_set_value(int service_num, unsigned int groupId, int value){
    struct multi_gpio_set_value_sender mgsv;
    mgsv.groupId = groupId;
    mgsv.service_num = service_num;
    mgsv.value = value;
    return ioctl(service_to_fd[service_num], REMOTE_GPIO_MULTI_WRITE, &mgsv);
}

void* thread_function(void* arg) {
    thread_arg_t* data = (thread_arg_t*)arg;
    int gpio = data->gpio;
    int service_num = data->service_num;
    int ret;
    while(1){
        ret = ioctl(service_to_fd[service_num], WAIT_INTERRUPT_SIGNAL, &gpio);
        if(ret < 0)
            break;
        data->function(service_num);
    }
    free(data);
    pthread_exit(NULL);
}

int remote_request_irq(int service_num, int port_num, unsigned int gpio, void* func, unsigned long flags, const char* name, const char* ip_addr){
    struct remote_request_irq_sender riq;
    riq.service_num = service_num;
    riq.port_num = port_num;
    riq.gpio = gpio;
    riq.flags = flags;
    strcpy(riq.name, name);
    strcpy(riq.ip_addr, ip_addr);
    thread_arg_t* thread_data = (thread_arg_t*)malloc(sizeof(thread_arg_t));
    thread_data->function = func;
    thread_data->gpio = gpio;
    thread_data->service_num = service_num;
    pthread_create(&thread[thread_idx], NULL, thread_function, (void*)thread_data);
    thread_idx++;

    return ioctl(service_to_fd[service_num], REMOTE_INTERRUPT_REQUEST, &riq);
}

int local_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label){
    struct local_request_gpio_one_arg_sender lrgo;
    strcpy(lrgo.label, label);
    lrgo.gpio = gpio;
    lrgo.flags = flags;
    return ioctl(service_to_fd[service_num], LOCAL_GPIO_REQUEST, &lrgo);
}


int local_gpio_free(int service_num, unsigned int gpio){
    struct local_gpio_free_arg_sender lgf;
    lgf.gpio = gpio;
    return ioctl(service_to_fd[service_num], LOCAL_GPIO_FREE, &lgf);
}



int local_gpio_set_value(int service_num, unsigned int gpio, int value){
    struct local_gpio_set_value_sender lgsv;
    lgsv.gpio = gpio;
    lgsv.value = value;
    return ioctl(service_to_fd[service_num], LOCAL_GPIO_WRITE, &lgsv);
}

int local_gpio_get_value(int service_num, unsigned int gpio){
    struct local_gpio_get_value_sender lggv;
    lggv.gpio = gpio;
    return ioctl(service_to_fd[service_num], LOCAL_GPIO_READ, &lggv);
}

int remote_free_irq(int service_num, unsigned int gpio){
    struct remote_free_irq_sender rfis;
    rfis.gpio = gpio;
    rfis.service_num = service_num;
    return ioctl(service_to_fd[service_num], REMOTE_FREE_IRQ, &rfis);
}

