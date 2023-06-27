# RPC-on-raspberry PI
This project is an RPC project designed to provide remote access to GPIO through simple function calls. Instead of using system calls, we designed the system to directly control sockets at the kernel level.

Below is an approximate structure of our project where we first load the implemented functions as a kernel module and then access them through a developed library to utilize the kernel functions:
<img width = "70%" src="https://user-images.githubusercontent.com/126436201/249140026-74e71820-c780-49aa-b4b7-81dbb9a12cef.png">



# Implemented RPC

1. int remote_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label);

   - this is the function that request remote GPIO.
2. int remote_gpio_free(int service_num, unsigned int gpio);

    - this is the function that release remote GPIO.
3. int remote_gpio_set_value(int service_num, unsigned int gpio, int value);

    - this is the function that write some value to GPIO
4. int remote_gpio_get_value(int service_num, unsigned int gpio);


    - this is function that read some value from GPIO
5. int remote_multi_gpio_request_one(int service_num, unsigned int gpio, unsigned long flags, char* label, int groudId);
  

    - this is function that request gpio and join GPIO to specified group ID
  
6. int remote_multi_gpio_free(int service_num, unsigned int gpio, int groudId);

    - this is function that release gpio and disjoin GPIO from specified group ID

7. int remote_multi_gpio_set_value(int service_num, unsigned int groupId, int value);

    - this is function that write value into gpio that join specified group ID 

8. int remote_request_irq(int service_num, int port_num, unsigned int gpio, void* func, unsigned long flags, const char* name, const char* ip_addr);

    - this is function that request interrupt into some GPIO.
    - you can receive interrupt through socket that has ip-address and port number that you specified.
    - after receiving interrupt, the process run function that you  

9. int remote_free_irq(int service_num, unsigned int gpio);
    - this is function that release interrupt fron some GPIO



# 
