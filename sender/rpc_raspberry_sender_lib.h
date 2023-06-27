
#define REMOTE_GPIOF_IN 0
#define REMOTE_GPIOF_OUT_INIT_LOW 1
#define REMOTE_GPIOF_OUT_INIT_HIGH 2

#define REMOTE_IRQF_TRIGGER_RISING 0x00000001
#define REMOTE_IRQF_TRIGGER_FALLING 0x00000002
#define REMOTE_IRQF_TRIGGER_HIGH 0x00000004
#define REMOTE_IRQF_TRIGGER_LOW 0x00000008

int connect_to_rasp(char* ip_addr, int port_num);
int disconnect_to_rasp(int service_num);
int remote_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label);
int remote_gpio_free(int service_num, unsigned int gpio);
int remote_gpio_set_value(int service_num, unsigned int gpio, int value);
int remote_gpio_get_value(int service_num, unsigned int gpio);
int remote_multi_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label, int groudId);
int remote_multi_gpio_free(int service_num, unsigned int gpio, int groudId);
int remote_multi_gpio_set_value(int service_num, unsigned int groupId, int value);
void* thread_function(void* arg);
int remote_request_irq(int service_num, int port_num, unsigned int gpio, void* func, unsigned long flags, const char* name, const char* ip_addr);
int local_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label);
int local_gpio_free(int service_num, unsigned int gpio);
int local_gpio_set_value(int service_num, unsigned int gpio, int value);
int local_gpio_get_value(int service_num, unsigned int gpio);
int remote_free_irq(int service_num, unsigned int gpio);