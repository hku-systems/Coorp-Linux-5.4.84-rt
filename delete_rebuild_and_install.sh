rm -rf /lib/modules/*5.4.84-rt47
rm -f /boot/*5.4.84-rt47
# rm -f /boot/vmlinuz
# rm -f boot/initrd.img
# ln -s /boot/vmlinuz-5.4.0-58-generic /boot/vmlinuz
# ln -s boot/initrd.img-5.4.0-58-generic /boot/initrd.img
cd linux-5.4.84-rt
make -j10
make modules_install -j10
cd /lib/modules/5.4.84-rt47
find . -name *.ko -exec strip --strip-unneeded {} +
cd -
make install -j10
