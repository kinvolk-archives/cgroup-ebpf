This repository experiments with [Daniel Mack](https://github.com/zonque)'s [eBPF hooks for
cgroups](https://github.com/torvalds/linux/commit/ca89fa77b4488ecf2e3f72096386e8f3a58fe2fc).

# Dependencies

* Linux >= v4.10-rc
* `CONFIG_CGROUP_BPF=y`
* cgroup2 hierarchy mounted (`mount -t cgroup2 none <mount point>`)

# Usage

Example:

```
#### cd into cgroup v2 hierarchy
cd /sys/fs/cgroup/unified

#### create new cgroup
mkdir demo

#### add a process
echo 1234 >>demo/cgroup.procs

sudo ./cgroup-ebpf out/ebpf.o /sys/fs/cgroup/unified/demo/
```

# Vendoring

We use [dep](https://golang.github.io/dep/).
