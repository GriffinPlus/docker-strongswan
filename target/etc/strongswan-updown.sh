#!/bin/sh

#
# Script that is called when strongswan establishes an SA or tears it down.
#
# It adds an entry to the neighbor proxy table, so connected clients can be "seen" from the internet 
#

set -e

case $PLUTO_VERB in
        up-client-v6)
        OUTDEV=$(ip -6 r get ${PLUTO_PEER_CLIENT%????}|sed -ne 's,^.*dev \(\S\+\) .*,\1,p')
        ip -6 neigh add proxy ${PLUTO_PEER_CLIENT%????} dev ${OUTDEV:-eth0}
        # ip -6 neigh show proxy
        ;;
        down-client-v6)
        OUTDEV=$(ip -6 r get ${PLUTO_PEER_CLIENT%????}|sed -ne 's,^.*dev \(\S\+\) .*,\1,p')
        ip -6 neigh delete proxy ${PLUTO_PEER_CLIENT%????} dev ${OUTDEV:-eth0}
        # ip -6 neigh show proxy
        ;;
esac
