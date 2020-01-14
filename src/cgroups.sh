mkdir /sys/fs/cgroup/memory/foo
mkdir /sys/fs/cgroup/cpu/foo
mkdir /sys/fs/cgroup/cpuset/foo
echo 5 > /sys/fs/cgroup/cpu/foo/cpu.shares
echo 1000000 > /sys/fs/cgroup/cpu/foo/cpu.cfs_quota_us
echo 1000000 > /sys/fs/cgroup/cpu/foo/cpu.cfs_period_us 
echo "0" > /sys/fs/cgroup/cpuset/foo/cpuset.cpus
echo 500000 > /sys/fs/cgroup/memory/foo/memory.limit_in_bytes
echo 0 > /sys/fs/cgroup/cpuset/foo/cpuset.mems

