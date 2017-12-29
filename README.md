# UNDER DEVELOPMENT - ***DO NOT USE IN PRODUCTION***

---------------------------------------------------------------------------

# Docker Image with StrongSwan

[![Build Status](https://travis-ci.org/cloudycube/docker-strongswan.svg?branch=master)](https://travis-ci.org/cloudycube/docker-strongswan) [![Docker 
Pulls](https://img.shields.io/docker/pulls/cloudycube/strongswan.svg)](https://hub.docker.com/r/cloudycube/strongswan) [![Github 
Stars](https://img.shields.io/github/stars/cloudycube/docker-strongswan.svg?label=github%20%E2%98%85)](https://github.com/cloudycube/docker-strongswan) [![Github 
Stars](https://img.shields.io/github/contributors/cloudycube/docker-strongswan.svg)](https://github.com/cloudycube/docker-strongswan) [![Github 
Forks](https://img.shields.io/github/forks/cloudycube/docker-strongswan.svg?label=github%20forks)](https://github.com/cloudycube/docker-strongswan)


## Overview
This is a Docker image deriving from the [base-supervisor](https://github.com/cloudycube/docker-base-supervisor) image. It adds the popular VPN software [StrongSwan](https://www.strongswan.org/) that allows you to create a VPN tunnel from common IKEv2 capable IPSec VPN clients right into your Docker stack. It can be useful, if you want to access your services remotely, but don't want your services (especially administration panels) to be visible on the public internet. This greatly reduces attack vectors malicious people can use to gain access to your system.

The image provides the following features:
- Dual-Stack Tunnel Broker (IPv4-over-IPv4, IPv4-over-IPv6, IPv6-over-IPv4, IPv6-over-IPv4)
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

The container needs your docker host to have IPv6 up and running. Please see [here](https://docs.docker.com/engine/userguide/networking/default_network/ipv6/) for details on how to enable IPv6 support.

### Step 1 - Configuring a User-Defined Network

One thing to consider is that resolving container names depends on docker's embedded DNS server. The DNS server resolves container names that are in the same user-defined networks as the strongswan container. If you do not already have an user-defined network for public services, you can create a simple bridge network (called *internet* in the example below) and define the subnets, from which docker will allocate ip addresses for containers. Most probably you will have only one IPv4 address for your server, so you should choose a subnet from the site-local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Docker takes care of connecting published services to the public IPv4 address of the server. Any IPv6 enabled server today has at least a /64 subnet assigned, so any single container can have its own IPv6 address, network address translation (NAT) is not necessary. Therefore you should choose an IPv6 subnet that is part of the subnet assigned to your server. Docker recommends to use a subnet of at least /80, so it can assign IP addresses by ORing the (virtual) MAC address of the container with the specified subnet.
```
docker network create -d bridge \
  --subnet 192.168.0.0/24 \
  --subnet 2001:xxxx:xxxx:xxxx::/80 \
  --ipv6 \
  internet
```

### Step 2 - Create a Volume for the StrongSwan Container

The strongswan container generates some data (e.g. keys, certificates, settings) that must be persisted. If you are familiar with docker you can also choose to map the data volume to your host, but *named volumes* are a more natural choice.

You can create a named volume using the following command:

```
docker volume create strongswan-data
```

### Step 3 - Run the StrongSwan Container

Although the container comes with a set of sensible default settings, some settings still need to be configured to suit your needs:

```
docker run \
  --ip6=<ip-address-in-network-internet> \
  --network internet
  --publish 500:500/udp \
  --publish 4500:4500/udp \
  --volume /lib/modules:/lib/modules:ro \
  --volume strongswan-data:/data \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --cap-add SYS_ADMIN \
  --env VPN_HOSTNAMES="vpn.my-domain.com" \
  cloudycube/strongswan
```

This starts the strongswan container and attaches it to the user-defined network *internet* that was created at [step 1](#step-1-configuring-a-user-defined-network) using the specified IPv6 address. The IPv6 address must be specified explicitly to ensure that the address is always the same - even, if the container is restarted. This is necessary, if you intend to create DNS records for the VPN server, so clients can use a readable and memorizable hostname instead of a long IPv6 address. The IPv4 address is automatically assigned by docker. Usually there is no need to enforce a certain IPv4 address, because docker maps published ports to the appropriate host interfaces.

The ports 500 (ISAKMP) and 4500 (NAT-Traversal) are published to tell docker to map these ports to all host interfaces. It is worth noticing that these port mappings only effect IPv4. IPv6 is not influenced by docker, so there is no filtering or firewalling done! The strongswan container takes care of this and implements a firewall to protect itself and connected VPN clients.

The container needs a few additional capabilities to work properly. The `NET_ADMIN` capability is needed to configure network interfaces and the firewall (iptables). The `SYS_MODULE` capability is needed to load kernel modules that are required for operation. The `SYS_ADMIN` capability is needed to remount the `/proc/sys` filesystem as read-write, so `sysctl` can configure network related settings. You can withdraw the `SYS_MODULE` capability and remove mapping `/lib/modules` into the container, if the `af_key` module is loaded when the container starts.

At last the container specific setting `VPN_HOSTNAMES` tells the container under which FQDNs the strongswan container will be seen on the internet. Multiple names can be separated by comma. You should list all names here that are published in the DNS. If you use the internal CA to create a server certificate (which is the default) these names are included in the server certificate.

The container can be configured using the following environment variables:

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

A subnet in the ULA range has the benefit that these IP addresses are not visible on the public internet. The IP addresses are only used by the VPN server and its clients to communicate with each other. There is no additional setup needed to get it working. Any communication with the public internet is done using *Masquerading*, a network address translation (NAT) technique that replaces internal IP addresses with the IP address of the VPN server for connections to the public internet. Although masquerading works really well for most protocols it can cause strange effects with some protocols, especially when multiple clients using the same protocol are involved. A tiny plus of using masquerading is that the IP address of a VPN client cannot be determined by visited sites as the IP address of the VPN server is used as the source address in packets.

You should consider [RFC 4193](https://tools.ietf.org/html/rfc4193) for details on how to choose a proper subnet from the ULA range. To cut a long story short, you should use the "randomly" generated approach (fd00::/8) and build the prefix using the following blueprint: `fdxx xxxx xxxx yyyy zzzz zzzz zzzz zzzz`, where *x* is a random site id, *y* is a random subnet id within the site and *z* is the hosts part within that subnet. This guarantees that the chosen subnet does not conflict with global addresses and makes it very unlikely to conflict with other subnets at your site.

##### Global Unicast Addresses (GUA)

A subnet in the GUA range has the benefit that VPN clients have direct access to the public internet and no network address translation (NAT) is needed that might cause issues with some protocols. By default new connections from the public internet to VPN clients are blocked by the internal firewall. Please see [PROTECT_CLIENTS_FROM_INTERNET](#protect_clients_from_internet) for details on how to disable this protection.

In order to use a GUA subnet you must configure your host to forward packets that are adressed to the specified subnet to the container, otherwise internet access will not work:
```
ip -6 route add <client-subnet> via <container-ip>
```

Default: `fd00:DEAD:BEEF:AFFE::/64` (ULA, Site-ID: `DEAD:BEEF`, Subnet-ID: `AFFE`)

#### DNS_SERVERS

Determines the DNS servers name resolution requests are forwarded to, if `USE_DOCKER_DNS` is `false`.

Default Value: `8.8.8.8, 8.8.4.4, 2001:4860:4860::8888, 2001:4860:4860::8844` (Google Public DNS)

#### PROTECT_CLIENTS_FROM_INTERNET

Determines whether VPN clients can be accessed from the public internet, i.e. whether new connections can be established from the public internet. Connections that are initiated by VPN clients are not effected. This setting only takes effect, if [CLIENT_SUBNET_IPV6](#client-subnet-ipv6) specifies a subnet in the GUA range.

- `true`, `1` => VPN clients are protected, i.e. they cannot be accessed from the public internet.
- `false`, `0` => VPN clients are not protected, i.e. they can be accessed from the public internet.

Default Value: `True`

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

Determines the fully qualified hostnames of the VPN server. The internal Certificate Authority will create a server certificate for these hostnames telling clients that they are connected to the desired VPN server. Multiple hostnames must be separated by comma.

Default Value: *hostname of the container*
