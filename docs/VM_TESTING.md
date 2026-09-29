# Setting up a safe test VM (for kernel-level work — NEXT phase)

Kernel-level prevention (eBPF / EndpointSecurity / WFP) can panic or boot-loop a machine on a
bug. **Never develop it on your daily machine.** Do it in a throwaway virtual machine you can
snapshot and reset. This guide sets that up.

## Why a VM
- A kernel bug in a VM crashes only the VM; your real Mac is untouched.
- Snapshots let you restore to "before the crash" in seconds.
- You can test Linux kernel hooks (eBPF) even from a Mac.

## Option A — Linux VM on your Mac (recommended first target: eBPF)
1. Install a free hypervisor: **UTM** (utm.app, native for Intel & Apple Silicon) or VirtualBox
   (Intel only).
2. Download a Linux ISO: **Ubuntu 24.04 LTS** (ubuntu.com/download).
3. Create a VM: 2 CPU, 4 GB RAM, 25 GB disk. Install Ubuntu in it.
4. **Take a snapshot** immediately after install, named "clean". This is your reset point.
5. Inside the VM:
   ```bash
   sudo apt update && sudo apt install -y python3-pip bpfcc-tools linux-headers-$(uname -r)
   git clone https://github.com/Talkachat/goodai-sentinel.git
   cd goodai-sentinel && pip install -e ".[test]"
   pytest -q            # confirm the user-space parts work in the VM first
   ```
6. Only then start kernel experiments. If the VM panics, restore the "clean" snapshot.

## Option B — cloud Linux VM (no local resources)
A small cloud instance (any provider) running Ubuntu works the same way; use provider snapshots
as reset points. Good if your Mac is low on disk/RAM.

## What we'll do there (next phase)
- Start with **eBPF in observe-only mode** (trace process/exec/connect events) — safe, no
  blocking, just richer visibility than polling.
- Validate the events match what the user-space sensors expect.
- Only after that's stable, experiment with **blocking** (eBPF LSM / seccomp), one hook at a
  time, snapshotting between each.
- macOS EndpointSecurity and Windows WFP are separate efforts needing Apple/MS developer
  signing; plan those after Linux eBPF is proven.

## Golden rule
Snapshot before every kernel experiment. If in doubt, restore. The whole point of the VM is
that mistakes cost seconds, not your machine.
