# macOS Hypervisor.framework: spike results

Findings that shaped the HVF backend for `solo5-hvt` on Apple Silicon. Each
one was measured on a MacBook with Apple Silicon running macOS 26.6.1
(25G76), `kern.hv_support: 1`, `hw.pagesize: 16384`. The spike programs live
outside this tree, in the fork's workspace (`spikes/`); this file records
what they showed and what was decided.

## 1. A 4 KiB IPA granule gives exact stage 2 W^X

Question: with 16 KiB host pages, can `hv_vm_protect()` apply different
permissions to 4 KiB pages inside one 16 KiB page, so that a guest linked
with the stock `max-page-size=0x1000` gets per-segment W^X?

Method: create the VM with `hv_vm_config_set_ipa_granule(HV_IPA_GRANULE_4KB)`
(public since macOS 26), map 64 MiB RWX at IPA 0, protect `[0x1000,0x2000)`
R, `[0x2000,0x3000)` RW and `[0x3000,0x4000)` X-only, and run a guest with
the MMU off that touches each page.

| Access | Expected | Result |
| --- | --- | --- |
| store to the R page | stage 2 data abort | data abort, IPA 0x1000 |
| store to the RW page | succeeds | succeeds |
| execute in the RW page | stage 2 instruction abort | instruction abort |
| execute in the X-only page | succeeds | succeeds |
| load from the X-only page | data abort (execute-only) | data abort |
| load from the R page | succeeds | succeeds |

With the default 16 KiB granule, the same 4 KiB `hv_vm_protect()` calls fail
with `HV_BAD_ARGUMENT` (0xfae94003). The default granule is 16 KiB.

Cost: a store loop with a 4 KiB stride over 63 MiB (built to defeat the TLB)
takes 8.4 ns per store with the 4 KiB granule against 3.7 ns with 16 KiB.
Workloads with ordinary locality see much less difference.

Decision: create every VM with a 4 KiB IPA granule and apply segment
permissions at stage 2 only. macOS 26 is the minimum. Execute-only works, so
`xnor` passes on macOS, which KVM cannot do.

## 2. A deny-all seatbelt profile is enough

Question: after the tender has set everything up, can it run under a
`sandbox_init(3)` profile without breaking `hv_vcpu_run()` or I/O on the
descriptors it already holds?

Method: open a block file, a socketpair, a pipe and a kqueue, create the VM
and vCPU, apply `(version 1) (deny default)`, then exercise everything.

Results under `(deny default)` with no allow rules at all:

- still work: `hv_vcpu_run()`, `pread`/`pwrite`/`fsync` on the
  pre-opened block file, `send`/`recv` on the pre-opened socketpair,
  pipe writes, `kevent()`, `clock_gettime()`, writes to stdout and stderr
- denied: `open()` of any path (including the block file again), file
  creation, `posix_spawn`, `fork`, `connect`/`sendto`/`bind` on new
  sockets (IPv4 and AF_UNIX)
- **not** mediated: `socket(2)` itself

Decision: the tender applies `(deny default)` and also lowers
`RLIMIT_NOFILE` to just above its highest open descriptor, so that
`socket()`, `pipe()`, `kqueue()` and so on fail with `EMFILE`. See
`tenders/hvt/hvt_sandbox_macos.c` and `tests/sandbox_macos/`.

## 3. RLIMIT_CPU livelocks hv_vcpu_run()

Found while implementing `--cpu-limit`: once a process has set `RLIMIT_CPU`
(any value, for example 100 seconds), `hv_vcpu_run()` spins at 100% CPU
inside `hv_trap` and the guest never executes its first instruction. The
same `setrlimit()` call in a process that does not use HVF behaves normally.

Decision: `--cpu-limit` is enforced by a watchdog thread that polls
`CLOCK_PROCESS_CPUTIME_ID` every 100 ms. This should be reported to Apple.

## 4. AF_UNIX datagram size on macOS

The maximum datagram on an AF_UNIX socket is bounded by the socket's send
buffer, 2 KiB by default (`net.local.dgram.maxdgram`). That is less than
a jumbo frame. Whoever creates the socketpair handed to the tender with
`--net:NAME=@NN` must raise `SO_SNDBUF` and `SO_RCVBUF` on both ends (the
test peer, `tests/netpeer`, uses 1 MiB). Set `--net-mtu:NAME=MTU` to
match what the peer can carry.

## 5. Startup and density

Measured with Mirage unikernels built from mirage-skeleton (Apple M4 Pro):

- `tutorial/noop`, start to exit, 50 sequential runs: median 13.5 ms, p95
  14.2 ms. This covers creating the VM, loading the ELF, entering the
  sandbox, booting the OCaml runtime and exiting.
- 32 concurrent `device-usage/clock` unikernels (`--mem=32`, mostly asleep):
  all running, about 13.6 MiB resident each (436 MiB total). Guest memory is
  `MAP_ANON` and only touched pages are resident.
- `device-usage/network` boots its TCP/IP stack and answers 10,000 pings over
  a socketpair in under 50 ms in total.
- `device-usage/http-fetch` (DHCP, DNS, TCP, TLS to the internet via vmnet)
  takes about 3 s end to end, dominated by the network.

No limit on the number of concurrent VMs was hit.

## 6. Other notes

- `hv_vcpu_create()` binds the vCPU to the calling thread, so the vCPU is
  created and run on the main thread, after the net I/O thread exists.
- HVF exposes the initial PSTATE of a vCPU that has not run as
  `HV_REG_CPSR`, and hands out the architectural reset value of
  `SCTLR_EL1` (its RES1 bits must be preserved).
- `cntfrq_el0` is 24 MHz on Apple Silicon. The guest gets it via
  `cpu_cycle_freq` as usual.
- GitHub's hosted macOS runners report `kern.hv_support: 0`
  (actions/runner-images#13505, closed as not planned), so running guests
  in CI needs a self-hosted Apple Silicon machine.
