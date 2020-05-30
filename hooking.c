#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/string.h>

static char * filewatch;

//charp - type of the parameter is string
module_param(filewatch, charp,0);
MODULE_PARM_DESC(filewatch,"destination file pointer");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("simple hooking driver");

//extract using cat /boot/System.map | grep sys_call
unsigned long *syscall_table = (unsigned long *)0xc07b0328;

//original system call signature
asmlinkage int (*original_sys_open)(const char* filename,int flags,int mode);

//hook function
asmlinkage int fake_sys_open(const char* filename, int flags,int mode)
{
 //check if open function requested on the filewatch
 if(strcmp(filename,filewatch) == 0)
 {
    //write to log
    printk("File open(\"%s\", %X, %X)\n", filename,flags,mode);
 
          //drop the request - operation not permitted
    return -EPERM;
 }
 
 //continue normal routine back to original function
 return (*original_sys_open)(filename,flags,mode);
}

static int init_driver(void) {

    printk("load hook module\n");
  
    //change read only area to write availability
    write_cr0 (read_cr0 () & (~ 0x10000));

    //save the original __NR_write pointer using uistd.h defines
    original_sys_open = (void *)syscall_table[__NR_open];

    //write to pointer to the fake function
    syscall_table[__NR_open] = fake_sys_open;

    //change the write area back to read only
    write_cr0 (read_cr0 () | 0x10000);

    return 0;
}

static void clean_driver(void) {

    //change read only area to write availability
    write_cr0 (read_cr0 () & (~ 0x10000));

    //return the original pointer to the system call table
    syscall_table[__NR_open] = original_sys_open;

    //change the write area back to read only
    write_cr0 (read_cr0 () | 0x10000);

    printk("unload hook module\n");

    return;
}
//pointing to custom init function when the module loaded
module_init(init_driver);

//pointing to custom cleanup function when the module unloaded
module_exit(clean_driver);
