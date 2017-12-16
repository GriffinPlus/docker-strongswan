config setup
    charondebug = "ike 3, knl 3, cfg 3, net 3, esp 3, dmn 3,  mgr 3"
    uniqueids = yes

ca strongswan
    cacert = ${ca_cert_path}
    # certuribase = http://ip6-winnetou.strongswan.org/certs/\n")
    # crluri = http://ip6-winnetou.strongswan.org/strongswan.crl\n")
    auto = add

conn %default
    keyexchange = ikev2
    dpdaction = clear
    dpddelay = 300s
    authby = pubkey
    rekey = no
    left = %any
    leftid = %any
    leftsubnet = 0.0.0.0/0
    leftcert = ${server_cert_path}
    leftsendcert = always
    leftfirewall = no
    right = %any
    rightsourceip = ${client_ip_range_start_ipv4}-${client_ip_range_end_ipv4}
    rightdns = ${own_ip_in_client_subnet_ipv4}
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
