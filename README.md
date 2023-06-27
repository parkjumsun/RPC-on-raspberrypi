# RPC-on-raspberrypi
This project is an RPC project designed to provide remote access to GPIO through simple function calls. Instead of using system calls, we designed the system to directly control sockets at the kernel level.

Below is an approximate structure of our project where we first load the implemented functions as a kernel module and then access them through a developed library to utilize the kernel functions:
<img src="



# Installation
Implemented RPC

1. 
