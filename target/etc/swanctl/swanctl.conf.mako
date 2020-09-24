connection-defaults {
    version = 2
    proposals = ${ike_proposals}
    rekey_time = 0s
    pools = primary-pool-ipv4, primary-pool-ipv6
    fragmentation = yes
    dpd_delay = 30s
    # dpd_timeout doesn't do anything for IKEv2. The general IKEv2 packet timeouts are used.
    send_cert = always
    send_certreq = yes
}

child-defaults {
    local_ts = 0.0.0.0/0, ::/0
    rekey_time = 0s
    dpd_action = clear
    esp_proposals = ${esp_proposals}
    updown = /etc/strongswan-updown.sh
}


connections {

    IKEv2-Pubkey : connection-defaults {
        local {
            auth = pubkey
            certs = ${server_cert_path}
            id = ${vpn_hostnames[0]}
        }
        remote {
            auth = pubkey
            eap_id = %any
        }
        children {
            ikev2-pubkey : child-defaults {
            }
        }
    }

    IKEv2-EAP : connection-defaults {
        local {
            auth = pubkey
            certs = ${server_cert_path}
            id = ${vpn_hostnames[0]}
        }
        remote {
            auth = eap-dynamic
            eap_id = %any
        }
        children {
            ikev2-eap : child-defaults {
            }
        }
    }

    IKEv2-EAP-TLS : connection-defaults {
        send_certreq = no
        local {
            auth = pubkey
            certs = ${server_cert_path}
            id = ${vpn_hostnames[0]}
        }
        remote {
            auth = eap-tls
            eap_id = %any
        }
        children {
            ikev2-eap-tls : child-defaults {
            }
        }
    }
}

pools {
    primary-pool-ipv4 {
        addrs = ${client_ip_range_start_ipv4}-${client_ip_range_end_ipv4}
        dns = ${own_ip_in_client_subnet_ipv4}
    }
    primary-pool-ipv6 {
        addrs = ${client_ip_range_start_ipv6}-${client_ip_range_end_ipv6}
        dns = ${own_ip_in_client_subnet_ipv6}
    }
}

authorities {
    local-ca {
        file = /data/internal_ca/ca-cert.pem
        crl_uris = file:///data/internal_ca/ca-crl.pem
    }
}
