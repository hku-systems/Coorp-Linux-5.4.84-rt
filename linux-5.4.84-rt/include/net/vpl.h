#ifndef FLOW_VPL
#define FLOW_VPL

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/ieee80211.h>
#include <linux/time.h>
#include <net/mac80211.h>

struct flow_tsf
{
    u64 ts_beacon;
    ktime_t ts_kernel;
    struct timespec64 ts_system;
};

#endif