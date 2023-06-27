#define MAX_CONNECTION 10
#define MAX_GROUP_NUM 10
#define GPIO_MAX 30

#define IOCTL_START_NUM 0x80
#define IOCTL_NUM1 IOCTL_START_NUM + 1
#define IOCTL_NUM2 IOCTL_START_NUM + 2
#define IOCTL_NUM3 IOCTL_START_NUM + 3
#define IOCTL_NUM4 IOCTL_START_NUM + 4
#define IOCTL_NUM5 IOCTL_START_NUM + 5
#define SIMPLE_IOCTL_NUM 'z'

#define INIT _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM1, unsigned long*)
#define WAIT_CONNECTION _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM2, unsigned long*)

#define GPIO_REQUEST_ONE 10
#define GPIO_REQUEST_WRITE 11
#define GPIO_REQUEST_READ 12
#define GPIO_REQUEST_FREE 13

#define MULTI_GPIO_REQUEST_ONE 20
#define MULTI_GPIO_REQUEST_WRITE 21
#define MULTI_GPIO_REQUEST_FREE 22

#define INTERRUPT_REQUEST 30
#define INTERRUPT_FREE 31


#define END_SIGNAL 100

struct request_gpio_one_arg_receiver{
    char label[20];
    unsigned int gpio;
    unsigned int flags;
};

struct gpio_free_arg_receiver{
    unsigned int gpio;
};

struct gpio_set_value_receiver{
    unsigned int gpio;
    int value;    
};

struct gpio_get_value_receiver{
    unsigned int gpio;
};

struct request_multi_gpio_one_arg_receiver{
    char label[20];
    unsigned int gpio;
    unsigned int flags;
    int groupIdx;
};

struct multi_gpio_free_arg_receiver{
    unsigned int gpio;
    int groupIdx;
};

struct multi_gpio_set_value_receiver{
    unsigned int groupId;
    int value;    
};

struct remote_request_irq_receiver{
    int port_num;
    unsigned int gpio;
    unsigned int flags;
    char name[20];  
    char ip_addr[20];
};

struct remote_free_irq_receiver{
    unsigned int gpio;
};
