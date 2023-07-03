# RPC-on-raspberry PI
This project is an RPC project designed to provide remote access to GPIO through simple function calls. Instead of using system calls, we designed the system to directly control sockets at the kernel level.

Below is an approximate structure of our project where we first load the implemented functions as a kernel module and then access them through a developed library to utilize the kernel functions:
<img width = "70%" src="https://user-images.githubusercontent.com/126436201/249140026-74e71820-c780-49aa-b4b7-81dbb9a12cef.png">

# project environment
This project is implemented in the C programming language and utilizes certain kernel functions. Therefore, it is necessary to install the appropriate kernel version to use it.
my test environment is like this
   - language: C
   - environment: Raspbian OS(kernel version 4.19) / ubuntu 20.04(kernel version 5.4.0)


# setup
first, you must compile c code and create .ko file. The provided makefile in conjunction with the code serves as a template for generating the .ko file. afterward the following steps can be followed to proceed with the project.

1. load kernel module
   - sudo insmod XX.ko
2. make device file
   - sudo sh mknod.sh
3. compile your own code including _lib.c file


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



# advanced feature
our project provide simple RPC function and two advanced RPC function.
advanced feature is like this.
1. multi writing
   This feature enables writing values simultaneously to multiple GPIOs. Here is an overview of how this functionality operates.

   <img width = "70%" src="https://user-images.githubusercontent.com/126436201/250567390-a9574ef5-9cdf-4f72-989d-d4dc2586fed8.png">

3. interrupt on socket
   This feature provide receving interrupt from remote and after receving doing some user defined function like interrupt handler
   Here is an overview of how this functionality operates.

   <img width = "70%" src="https://user-images.githubusercontent.com/126436201/250572560-40eccd0a-72c1-4090-be4e-00e61b6cb8ee.png">
   <img width = "70%" src="https://user-images.githubusercontent.com/126436201/250572765-dacaec07-8745-4415-b6b5-d34f80c4d96f.png">

