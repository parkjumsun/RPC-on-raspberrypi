#include "rpc_raspberry_receiver.h"
#include <string.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>


int fd;

int init_rpc(unsigned long portnum){
    fd = open("/dev/rpc_raspberry_receiver", O_RDWR);
    if(fd < 0)
        return -1;
    unsigned long portnum_lib = portnum;
    ioctl(fd, INIT, &portnum_lib);
    return fd;
}

int wating_from_sender(int fd){
    int ret = ioctl(fd, WAIT_CONNECTION, NULL);
    return ret;
}


int main(int argc, char const *argv[])
{   
    int fd = init_rpc(700);
    while(1){
        wating_from_sender(fd);
    }
    close(fd);
    return 0;
}
