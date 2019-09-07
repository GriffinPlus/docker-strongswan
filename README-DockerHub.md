# Docker Image with StrongSwan

[![Build Status](https://dev.azure.com/griffinplus/Docker%20Images/_apis/build/status/7?branchName=master)](https://dev.azure.com/griffinplus/Docker%20Images/_build/latest?definitionId=7&branchName=master)
[![Docker Pulls](https://img.shields.io/docker/pulls/griffinplus/strongswan.svg)](https://cloud.docker.com/r/griffinplus/strongswan)
[![Github Stars](https://img.shields.io/github/stars/griffinplus/docker-strongswan.svg?label=github%20%E2%98%85)](https://github.com/griffinplus/docker-strongswan)
[![Github Contributors](https://img.shields.io/github/contributors/griffinplus/docker-strongswan.svg)](https://github.com/griffinplus/docker-strongswan)
[![Github Forks](https://img.shields.io/github/forks/griffinplus/docker-strongswan.svg?label=github%20forks)](https://github.com/griffinplus/docker-strongswan)


## Overview
This is a Docker image deriving from the [base-supervisor](https://github.com/GriffinPlus/docker-base/tree/master/base-supervisor) image. It adds the popular VPN software [StrongSwan](https://www.strongswan.org/) that allows you to creat
e a VPN tunnel from common IKEv2 capable IPSec VPN clients right into your Docker stack. It can be useful, if you want to access your services remotely, but don't want your services (especially administration panels) to be visible on the
 public internet. This greatly reduces attack vectors malicious people can use to gain access to your system.

The image provides the following features:
- StrongSwan Version 5.8.0
- Road Warrior Setup for Remote Access / Mobile Devices
- Dual-Stack Tunnel Broker (IPv4-over-IPv4, IPv4-over-IPv6, IPv6-over-IPv4, IPv6-over-IPv4)
- Authentication Methods
  - IKEv2 certificate authentication
  - IKEv2 EAP-TLS (certificate authentication)
- Internal Certificate Authority
  - Creates a server certificate for StrongSwan and client certificates to authenticate VPN clients
  - Supports RSA/ECC certificates
    - RSA: 2048/3072/4096 bit
    - ECC: secp256r1 (NIST/SECG curve over a 256 bit prime field) (aka P-256, prime256v1)
    - ECC: secp384r1 (NIST/SECG curve over a 384 bit prime field) (aka P-384)
    - ECC: secp521r1 (NIST/SECG curve over a 521 bit prime field) (aka P-521)
- Internal DNS forwarder provides name resolution services to VPN clients using...
  - Docker's embedded DNS (containers can be accessed by their name)
  - External DNS servers
- High performance by using the kernel's NETKEY IPSec stack (kernel 2.6+)
- Communication between VPN clients
- Internet access over the VPN
  - IPv4: Masquerading
  - IPv6: Masquerading / Global Unicast Address (GUA)
- Tested Clients
  - Windows 10 Integrated VPN Client (Desktop)
  - Android [StrongSwan App](https://play.google.com/store/apps/details?id=org.strongswan.android)

------------------------------------------------------------------------------------------------------------------------

More information is available on the [project site](https://github.com/GriffinPlus/docker-strongswan).
