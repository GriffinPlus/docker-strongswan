# UNDER DEVELOPMENT - ***DO NOT USE IN PRODUCTION***

---------------------------------------------------------------------------

# Docker Image with StrongSwan

[![Build Status](https://travis-ci.org/cloudycube/docker-strongswan.svg?branch=master)](https://travis-ci.org/cloudycube/docker-strongswan) [![Docker 
Pulls](https://img.shields.io/docker/pulls/cloudycube/strongswan.svg)](https://hub.docker.com/r/cloudycube/strongswan) [![Github 
Stars](https://img.shields.io/github/stars/cloudycube/docker-strongswan.svg?label=github%20%E2%98%85)](https://github.com/cloudycube/docker-strongswan) [![Github 
Stars](https://img.shields.io/github/contributors/cloudycube/docker-strongswan.svg)](https://github.com/cloudycube/docker-strongswan) [![Github 
Forks](https://img.shields.io/github/forks/cloudycube/docker-strongswan.svg?label=github%20forks)](https://github.com/cloudycube/docker-strongswan)


## Overview
This is a Docker image deriving from the [base-supervisor](https://github.com/cloudycube/docker-base-supervisor) image. It adds the popular VPN software [StrongSwan](https://www.strongswan.org/) that allows you to create a VPN tunnel from common IKEv2 capable IPSec VPN clients right into your Docker stack. This can be useful, if you want to access your services remotely, but don't want your services (especially administration panels) to be visible on the public internet. This greatly reduces attack vectors malicious people can use to gain access to your system.

The image provides the following features:
- Full Support for IPv4 and IPv6
- Support for IKEv2 only
- Authentication Methods
  - IKEv2 certificate authentication
  - IKEv2 EAP-TLS (certificate authentication)
- Internal Certificate Authority
  - Automatic and Self-Maintaining (no need to handle cryptographic stuff manually)
  - Creates a self-signed server certificate for StrongSwan
  - Creates client certificates to authenticate VPN clients
- Internal DNS forwarder provides name resolution services to VPN clients using...
  - Docker's embedded DNS (containers can be accessed by their name)
  - External DNS servers
- Communication between VPN clients
- Internet access over the VPN
  - IPv4: Masquerading
  - IPv6: Masquerading / Global Unicast Address (GUA)

This image belongs to a set of Docker images created for project [CloudyCube](https://www.falk-online.eu/projekte/cloudycube). The homepage is in German only, but you will find everything needed to get it working here as well.


## Usage

Although the container comes with a set of sensible default settings, it is recommended to set some settings explicitly to suit your needs:
```
docker run \
  --env VPN_HOSTNAMES="vpn.my-domain.com" \
  --env CLIENT_SUBNET_IPV4="10.0.0.0/24" \
  --env CLIENT_SUBNET_IPV6="fd00:DEAD:BEEF::/112" \
  cloudycube/strongwan
```
Please replace the FQDN via which the VPN server is reachable from the internet and the subnets from which client IP addresses are assigned. In the example above the VPN server will take `10.0.0.1` and `fc00:DEAD:BEEF::1` as its own internal address and assign IPv4 addresses from `10.0.0.2` to `10.0.0.254` and IPv6 addresses from `fd00:DEAD:BEEF::2` to `fd00:DEAD:BEEF::FF` to connecting VPN clients.

### Environment Variables

#### ALLOW_INTERNET_ACCESS

Determines whether VPN clients are allowed to access the internet.

- `true`, `1` => VPN clients are allowed to access the internet.
- `false`, `0` => VPN clients are not allowed to access the internet.

Default Value: `true`

#### ALLOW_INTERCLIENT_COMMUNICATION

Determines whether VPN clients are allowed to communicate with each other.

- `true`, `1` => VPN clients are allowed to communicate with each other.
- `false`, `0` => VPN clients are not allowed to communicate with each other.

Default Value: `false`

#### CLIENT_SUBNET_IPV4

Determines the subnet from which IPv4 addresses are assigned to VPN clients. The subnet should be one of the following or a subnet of one of them to avoid conflicts with global addresses:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

Default: `10.0.0.0/24`

#### CLIENT_SUBNET_IPV6

Determines the subnet from which IPv6 addresses are assigned to VPN clients. The subnet can either be a subnet in the *Unique Local Unicast Address (ULA, fc00::/7)* range or in the *Global Unicast Address (GUA, 2000::/3)* range.

##### Unique Unicast Addresses (ULA)
A subnet in the ULA range has the benefit that these IP addresses are not visible on the public internet, the IP addresses are only used by the VPN server and its clients to communicate with each other. There is no additional setup needed to get it working. Any communication with the public internet is done using *Masquerading*, a network address translation (NAT) technique that replaces internal IP addresses with the IP address of the VPN server for connections to the public internet. Although masquerading works really well for most protocols it can cause strange effects with some protocols, especially when multiple clients using the same protocol are involved. A tiny plus of using masquerading is that the IP address of a VPN client cannot be determined by visited sites as the IP address of the VPN server is used as the sender address in packets.

You should consider [RFC 4193](https://tools.ietf.org/html/rfc4193) for details on how to choose a proper subnet from the ULA range. To cut a long story short, you should use the "randomly" generated approach (fd00::/8) and build the prefix using the following blueprint: `fdxx xxxx xxxx yyyy zzzz zzzz zzzz zzzz`, where *x* is a random site id, *y* is a random subnet id within the site and *z* is the hosts part within that subnet. This guarantees that the chosen subnet does not conflict with global addresses and makes it very unlikely to conflict with other subnets at your site.

##### Global Unicast Addresses (GUA)

TODO

Default: `fd00:DEAD:BEEF:AFFE::/64` (ULA, Site-ID: `DEAD:BEEF`, Subnet-ID: `AFFE`)

#### DNS_SERVERS

Determines the DNS servers name resolution requests are forwarded to, if `USE_DOCKER_DNS` is `false`.

Default Value: `8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844` (Google Public DNS)

#### STARTUP_VERBOSITY

Determines the verbosity of the *CloudyCube Container Startup System* (see [here](https://github.com/cloudycube/docker-base-supervisor) for details).

- 0 => Only errors are logged.
- 1 => Errors and warnings are logged.
- 2 => Errors, warnings and notes are logged.
- 3 => All messages (incl. debug) are logged.

Default Value: `2`

#### USE_DOCKER_DNS

Determines whether the built-in DNS server forwards name resolution requests to Docker's embedded DNS server.

- `true`, `1` => Docker's Embedded DNS Server is used (containers in user-defined networks can be accessed by their name).
- `false`, `0` => External DNS servers are used (see [DNS_SERVERS](#dns_servers)).

Default Value: `true`

#### USE_INTERNAL_PKI

Determines whether to use the internal Certificate Authority (CA) for creating a certificate for the VPN server and its clients.

- `true`, `1` => The internal Certificate Authority is used.
- `false`, `0` => An external Certificate Authority is used.

Default Value: `true`

#### VPN_HOSTNAMES

Determines the fully qualified hostnames of the VPN server. The internal Certificate Authority will create a server certificate for these hostnames telling clients that they are connected to the desired VPN server. Multiple hostnames must be comma-separated.

Default Value: *hostname of the container*
