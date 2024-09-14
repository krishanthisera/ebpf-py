#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-verifier.h"

int c = 1;
char message[12] = "Hello World";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");


// make && \
//   rm  /sys/fs/bpf/hello-verifier && \
//   bpftool prog load hello-verifier.bpf.o /sys/fs/bpf/hello-verifier
// Changing this from "xdp" will cause the verifier to fail
// ---
// 16: (85) call bpf_get_current_pid_tgid#14
// unknown func bpf_get_current_pid_tgid#14
SEC("kprobe") 
int kprobe_exec(void *ctx)
{
   struct data_t data = {}; 
   struct msg_t *p;
   u64 uid;

   data.counter = c; 
   c++; 

   data.pid = bpf_get_current_pid_tgid();
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.uid = uid;

   // The first argument needs to be a pointer to a map; the following won't be accepted 
   // p = bpf_map_lookup_elem(&data, &uid);
   // ---
   // reg type unsupported for arg#0 function kprobe_exec#23
   // ...
   // 27: (85) call bpf_map_lookup_elem#1
   // R1 type=fp expected=map_ptr
   p = bpf_map_lookup_elem(&my_config, &uid);
 

   // Attempt to dereference a potentially null pointer
   // ---
   // ; char a = p->message[0];
   // 29: (71) r3 = *(u8 *)(r7 +0)
   // R7 invalid mem access 'map_value_or_null'
   // processed 28 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
   if (p != 0) {
      char a = p->message[0];
      bpf_printk("%d", a);        
   }

   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);  
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   // Changing this to <= means and c could have value beyond the bounds of the
   // global message array
   // if (c <= sizeof(message)) {
   if (c < sizeof(message)) {
      char a = message[c];
      bpf_printk("%c", a);
   }

   // Changing this to <= means and c could have value beyond the bounds of the
   // data.message array
   // if (c <= sizeof(data.message)) {
   if (c < sizeof(data.message)) {
      char a = data.message[c];
      bpf_printk("%c", a);
   } 

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU,  &data, sizeof(data));

   return 0;
}

SEC("xdp")
int xdp_hello(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Attempt to read outside the packet
  // ---
  // ; data_end++;
  // 2: (07) r4 += 1
  // R4 pointer arithmetic on pkt_end prohibited
  // data_end++; 

   // This is a loop that will pass the verifier
   // for (int i=0; i < 10; i++) {
   //    bpf_printk("Looping %d", i);
   // }

   // This is a loop that will fail the verifier
   for (int i=0; i < c; i++) {
      bpf_printk("Looping %d", i);
   }

   // Comment out the next two lines and there won't be a return code defined
   // If comment all includuding the helper funcitons, the verifier will fail
   //  but if we have the helper functions, the verifier will use the return from the helper function
   // ---
   // 0: R1=ctx(off=0,imm=0) R10=fp0
   // ; }
   // 0: (95) exit
   // R0 !read_ok
  bpf_printk("%x %x", data, data_end);
  return XDP_PASS;
}

// Removing the license section means the verifier won't let you use
// GPL-licensed helpers
// The gpl_only field is set to true for the bpf_probe_read_kernel()
// See https://lore.kernel.org/bpf/796ee46e948bc808d54891a1108435f8652c6ca4.1572649915.git.daniel@iogearbox.net/
// ---
// cannot call GPL-restricted function from non-GPL compatible program
// processed 35 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
char LICENSE[] SEC("license") = "Dual BSD/GPL";
