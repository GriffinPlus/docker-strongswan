options {
    directory "/var/cache/bind";
    recursion yes;
    allow-query { 127.0.0.1; ${client_subnet_ipv4}; };
    forwarders { ${"; ".join(dns_servers)}; };
    forward only;
};

