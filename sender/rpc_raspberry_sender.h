#define MAX_CONNECTION 10
#define MAX_GROUP_NUM 10
#define GPIO_MAX 30


#define REMOTE_IRQF_TRIGGER_RISING 0x00000001
#define REMOTE_IRQF_TRIGGER_FALLING 0x00000002
#define REMOTE_IRQF_TRIGGER_HIGH 0x00000004
#define REMOTE_IRQF_TRIGGER_LOW 0x00000008

#define REMOTE_GPIOF_IN 0
#define REMOTE_GPIOF_OUT_INIT_LOW 1
#define REMOTE_GPIOF_OUT_INIT_HIGH 2


#define IOCTL_START_NUM 0x80
#define IOCTL_NUM1 IOCTL_START_NUM + 1
#define IOCTL_NUM2 IOCTL_START_NUM + 2
#define IOCTL_NUM3 IOCTL_START_NUM + 3
#define IOCTL_NUM4 IOCTL_START_NUM + 4
#define IOCTL_NUM5 IOCTL_START_NUM + 5
#define IOCTL_NUM6 IOCTL_START_NUM + 6
#define IOCTL_NUM7 IOCTL_START_NUM + 7
#define IOCTL_NUM8 IOCTL_START_NUM + 8
#define IOCTL_NUM9 IOCTL_START_NUM + 9
#define IOCTL_NUM10 IOCTL_START_NUM + 10
#define IOCTL_NUM11 IOCTL_START_NUM + 11
#define IOCTL_NUM12 IOCTL_START_NUM + 12
#define IOCTL_NUM13 IOCTL_START_NUM + 13
#define IOCTL_NUM14 IOCTL_START_NUM + 14
#define IOCTL_NUM15 IOCTL_START_NUM + 15
#define IOCTL_NUM16 IOCTL_START_NUM + 16
#define SIMPLE_IOCTL_NUM 'z'


#define CONNECT_TO_RASP _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM1, unsigned long*)
#define DISCONNECT_TO_RASP _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM2, unsigned long*)
#define REMOTE_GPIO_REQUEST _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM3, unsigned long*)
#define REMOTE_GPIO_WRITE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM4, unsigned long*)
#define REMOTE_GPIO_READ _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM5, unsigned long*)
#define REMOTE_GPIO_FREE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM6, unsigned long*)

#define REMOTE_MULTI_GPIO_REQUEST _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM7, unsigned long*)
#define REMOTE_GPIO_MULTI_WRITE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM8, unsigned long*)
#define REMOTE_GPIO_MULTI_FREE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM9, unsigned long*)
#define REMOTE_INTERRUPT_REQUEST _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM10, unsigned long*)
#define WAIT_INTERRUPT_SIGNAL _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM11, unsigned long*)
#define REMOTE_FREE_IRQ _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM16, unsigned long*)

#define LOCAL_GPIO_REQUEST _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM12, unsigned long*)
#define LOCAL_GPIO_WRITE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM13, unsigned long*)
#define LOCAL_GPIO_READ _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM14, unsigned long*)
#define LOCAL_GPIO_FREE _IOWR(SIMPLE_IOCTL_NUM, IOCTL_NUM15, unsigned long*)


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


struct socket_args {
    char ip_addr[20];
    int port_num;
};

struct request_gpio_one_arg_sender{
    int service_num;
    char label[20];
    unsigned int gpio;
    unsigned int flags;
};

struct gpio_free_arg_sender{
    int service_num;
    unsigned int gpio;
};


struct gpio_set_value_sender{
    int service_num;
    unsigned int gpio;
    int value;    
};

struct gpio_get_value_sender{
    int service_num;
    unsigned int gpio;
};

struct request_multi_gpio_one_arg_sender{
    int service_num;
    char label[20];
    unsigned int gpio;
    unsigned int flags;
    int groupIdx;
};

struct multi_gpio_free_arg_sender{
    int service_num;
    unsigned int gpio;
    int groupIdx;
};

struct multi_gpio_set_value_sender{
    int service_num;
    unsigned int groupId;
    int value;    
};

struct remote_request_irq_sender{
    int service_num;
    int port_num;
    unsigned int gpio;
    unsigned int flags;
    char name[20];
    char ip_addr[20];
};

struct local_request_gpio_one_arg_sender{
    char label[20];
    unsigned int gpio;
    unsigned int flags;
};

struct local_gpio_free_arg_sender{
    unsigned int gpio;
};

struct local_gpio_set_value_sender{
    unsigned int gpio;
    int value;    
};

struct local_gpio_get_value_sender{
    unsigned int gpio;
};

struct remote_free_irq_sender{
    int service_num;
    unsigned int gpio;
};
