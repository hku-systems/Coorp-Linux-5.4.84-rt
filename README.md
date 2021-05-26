# Using linux5.4.84-rt with vritual-preemption layer

## First Time to Compile and Install the Hooked Linux Kernel
Make sure you exported symbols of your WNIC driver in the Kernel.
1. cd linux-5.4.84-rt
2. make menuconfig
3. gerenral setup -> preemption module: real time; then save and exit the .config file
4. make -j10
5. make modules_install -j10
6. make install -j10
7. reboot and boot with linux5.4.84-rt as your kernel

## Iterative development on the Linux Kernel
You may try our script:
1. sudo bash delete_rebuild_and_install.sh 

## Using the virtual-preemption layer
Make sure you modified symbols in vpl.c according to the exported symbols of your WNIC driver.
1. cd virtual_preemption_layer
2. make
3. sudo insmod vpl.ko
4. Then you may use vpl.py in Predar directly.

 