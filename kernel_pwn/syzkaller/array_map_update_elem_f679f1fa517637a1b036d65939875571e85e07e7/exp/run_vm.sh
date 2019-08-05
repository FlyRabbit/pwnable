qemu-system-x86_64 \
  -m 128M \
  -smp 2 -gdb tcp::1234 \
  -enable-kvm \
  -net nic,model=e1000 \
  -net user,host=10.0.2.10,hostfwd=tcp::1569-:22 -redir tcp:3777::3777 \
  -display none -serial stdio -no-reboot \
  -hda /home/etenal/project/code/pwn/syzkaller/array_map_update_elem/img/2881fc2/stretch.img \
  -kernel /home/etenal/project/code/pwn/syzkaller/array_map_update_elem/linux-4.15/arch/x86_64/boot/bzImage \
  -append "console=ttyS0 net.ifnames=0 root=/dev/sda"
