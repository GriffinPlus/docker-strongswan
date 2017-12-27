options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { 127.0.0.1; ${client_subnet_ipv4.with_prefixlen}; ${client_subnet_ipv6.with_prefixlen}; };
    forwarders { ${"; ".join(dns_servers)}; };
    forward only;
};
