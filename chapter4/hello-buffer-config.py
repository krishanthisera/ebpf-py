#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = r"""
struct user_msg_t {
   char msg[12];
};

BPF_HASH(config, u32, struct user_msg_t);

BPF_PERF_OUTPUT(output); 

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char msg[12];
};

int hello(void *ctx) {
   struct data_t data = {}; 
   struct user_msg_t *p;
   char msg[12] = "Hello World";

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));

   p = config.lookup(&data.uid);
   if (p != 0) {
      bpf_probe_read_kernel(&data.msg, sizeof(data.msg), p->msg);       
   } else {
      bpf_probe_read_kernel(&data.msg, sizeof(data.msg), msg); 
   }

   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
# b.attach_kprobe(event=syscall, fn_name="hello")
# Attaching to raw tracepoint
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")
b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(501)] = ct.create_string_buffer(b"Hi user 501!")

 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   # print(f"{data.pid} {data.uid} {data.command.decode()} {data.msg.decode()}")
 
b["output"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()
