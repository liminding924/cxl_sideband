#########################################################################
# File Name: setup.sh
# Desc:
# Author: Andy-wei.hou
# mail: wei.hou@scaleflux.com
# Created Time: 2025年11月25日 星期二 15时25分36秒
# Log: 2026-10-28 EIDS: one mctp_bridge instance per remote EID
#########################################################################
#!/bin/bash
#
# EIDS lists the remote EIDs, one bridge instance each (default "8"):
#   EIDS="8 10" ./setup.sh
# routes EID 8 via mctp_bridge0 (/dev/mctp_bridge) and EID 10 via
# mctp_bridge1 (/dev/mctp_bridge1). Then run one bridge per device:
#   ./bridge --tcp host:port                                  # EID 8
#   ./bridge --dev /dev/mctp_bridge1 --dev-eid 10 --udp ...   # EID 10

EIDS=${EIDS:-8}
LOCAL_EID=${LOCAL_EID:-19}
set -- $EIDS
NR_DEVS=$#

sudo rmmod mctp_bridge
sudo insmod mctp_bridge.ko nr_devs=$NR_DEVS

i=0
for eid in $EIDS; do
    dev=mctp_bridge$i

    ## enable netdev
    sudo ip link set $dev up

    ## CFG route and address bind
    ### remote EID
    sudo mctp route add $eid via $dev
    #sudo mctp address add $eid dev $dev

    ### set the local dev eid so bind/recvfrom can get msg; every instance
    ### needs one, sendto() takes the source EID from the output netdev
    ### (EHOSTUNREACH without it). The same EID may sit on several netdevs.
    sudo mctp address add $LOCAL_EID dev $dev

    ## show route & eid cfg
    sudo mctp link show $dev
    sudo mctp route show $dev
    sudo mctp address show $dev
    i=$((i + 1))
done
