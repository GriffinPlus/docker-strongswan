# /etc/strongswan.conf - strongSwan configuration file
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details

charon {
    load_modular = yes
% if len(interfaces) > 0:
    interfaces_use = ${','.join(interfaces)}
% endif
    send_vendor_id = yes

    plugins {
        include strongswan.d/charon/*.conf
    }

    start-scripts {
        load-all = /usr/sbin/swanctl --load-all
    } 

    # logger configuration
    # see https://wiki.strongswan.org/projects/strongswan/wiki/LoggerConfiguration

    filelog {
        charon {
            # path of the log file
            path = /var/log/charon.log
            # add a timestamp prefix
            time_format = %b %e %T
            # prepend connection name, simplifies grepping
            ike_name = yes
            # overwrite existing files
            append = no
            # increase default loglevel for all daemon subsystems except encoding (enc)
            default = 2
            enc = 1
            # flush each line to disk
            flush_line = yes
        }
    }
    stderr {
        # more detailed loglevel for a specific subsystem, overriding the
        # default loglevel.
        ike = 2
        knl = 3
    }
}

include strongswan.d/*.conf
