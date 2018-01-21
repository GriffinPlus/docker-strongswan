config setup
    charondebug = "ike 3, knl 3, cfg 3, net 3, esp 3, dmn 3,  mgr 3"
    strictcrlpolicy = yes
    uniqueids = yes

conn %default
    keyexchange = ikev2
    dpdaction = clear
    dpddelay = 300s
    authby = pubkey
    rekey = no
    fragmentation = yes
    left = %any
    leftid = %any
    leftsubnet = 0.0.0.0/0, 0::/0
    leftcert = ${server_cert_path}
    leftsendcert = always
    leftfirewall = no
    right = %any
    rightsourceip = ${client_ip_range_start_ipv4}-${client_ip_range_end_ipv4}, ${client_ip_range_start_ipv6}-${client_ip_range_end_ipv6}
    rightdns = ${own_ip_in_client_subnet_ipv4}, ${own_ip_in_client_subnet_ipv6}

conn IKEv2-Pubkey
    leftauth = pubkey
    rightauth = pubkey
    leftsendcert = always
    rightsendcert = always
    auto = add

conn IKEv2-EAP
    eap_identity = %any
    rightauth = eap-dynamic

conn IKEv2-EAP-TLS
    eap_identity = %any
    leftauth = pubkey
    rightauth = eap-tls
    rightsendcert = never
    auto = add
