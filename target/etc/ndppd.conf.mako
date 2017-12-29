proxy eth0 {
  timeout 500
  ttl 30000
  rule ${client_subnet_ipv6} {
    static
  }
}
