# Trace Linux boot
-- OSH lab01
## ENVIRONMENT
- Archlinux with kernel 4.15.13-1-ARCH
- qemu 2.11.1-2
- gdb 8.1
- gcc 7.3.1
## establish of lab environment
- clone the kernel source: [https://github.com/torvalds/linux](https://github.com/torvalds/linux)
```sh
git clone https://github.com/torvalds/linux.git
```
- compile
```sh
make menuconfig
make -j8 bzImage
```
during make menuconfig, select Kernel hacking->Compile-time->checks and compiler options->Compile the kernel with debug info, which can guarantee the debug info included in the kernel
- create virtual disk and format
```sh
qemu-img create disk.img 1g
mkfs.ext4 disk.img
```
- create Archlinux bootstrap
```sh
mkdir root.x86_64
mount -o loop disk.img root.x86_64
aria2c https://mirrors.ustc.edu.cn/archlinux/iso/latest/archlinux-bootstrap-2018.04.01-x86_64.tar.gz
tar xzf <path-to-bootstrap-image>/archlilnux-bootstrap-2018.04.01-x86_64.tar.gz
cp /usr/bin/init root.x86_64/usr/bin/
cp /usr/bin/shutdown root.x86_64/usr/bin
umount root.x86_64
```
there is the tutor in archwiki: [Install from existing Linux](https://wiki.archlinux.org/index.php/Install_from_existing_Linux#Creating_the_chroot)
, and the bootstrap didn't have init and command, to make the bootstrap can init, I copy the init binary in local system to the disk image.

Then I use `qemu-system-x86_64 -kernel arch/x86/boot/bzImage -hda disk.img -append "root=/dev/sda console=ttyS0 nokaslr " -s -S --nographic` to boot qemu, and type `./gdb.sh` to boot gdb and break at function start_kernel()