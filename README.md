# UNDER DEVELOPMENT - ***DO NOT USE IN PRODUCTION***

---------------------------------------------------------------------------

# Docker Image with StrongSwan

[![Build Status](https://travis-ci.org/cloudycube/docker-strongswan.svg?branch=master)](https://travis-ci.org/cloudycube/docker-strongswan) [![Docker 
Pulls](https://img.shields.io/docker/pulls/cloudycube/strongswan.svg)](https://hub.docker.com/r/cloudycube/strongswan) [![Github 
Stars](https://img.shields.io/github/stars/cloudycube/docker-strongswan.svg?label=github%20%E2%98%85)](https://github.com/cloudycube/docker-strongswan) [![Github 
Stars](https://img.shields.io/github/contributors/cloudycube/docker-strongswan.svg)](https://github.com/cloudycube/docker-strongswan) [![Github 
Forks](https://img.shields.io/github/forks/cloudycube/docker-strongswan.svg?label=github%20forks)](https://github.com/cloudycube/docker-strongswan)

## Overview
This is a Docker image deriving from the [base-supervisor](https://github.com/cloudycube/docker-base-supervisor) image. It adds the popular VPN software [StrongSwan](https://www.strongswan.org/) that allows you to create a VPN tunnel from any IPSec capable client right into your Docker stack. This can be useful, if you want to access your services remotely, but don't want your services (especially administration panels) to be visible on the public internet. This greatly reduces attack vectors malicious people can use to gain access to your system.

This image belongs to a set of Docker images created for project [CloudyCube](https://www.falk-online.eu/projekte/cloudycube). The homepage is in German only, but you will find everything needed to get it working here as well.

## For Users

### Environment Variables

#### USE_INTERNAL_CA

Determines whether to use the internal Certificate Authority (CA) for creating a certificate for the VPN server and its clients.

- `true`, `1` => The internal Certificate Authority is used (see [here](#internal-certificate-authority) for additional information)
- `false`, `0` => An external Certificate Authority is used (see [here](#external-certificate-authority) for additional information).

Default Value: `true`

#### VPN_HOSTNAME

Fully qualified hostname of the VPN server. The internal Certificate Authority will create a server certificate for that hostname telling clients that they are connected to the desired VPN server.

Default Value: *hostname of the container*

### Certificate Authorities

The Certificate Authority (CA) is the anchor of trust in your Public Key Infrastructure (PKI). Everyone dealing with the VPN Server must trust it. This is usually done by importing the CA certificate as a trusted Root CA in all devices taking part.

The CA is responsible for issuing a certificate for the VPN server and its clients. Everyone in the PKI trusts the CA, so the CA is able to issue additional certificates everyone trusting the CA will trust as well. Clients that trust the CA will know that the VPN server they are talking to is authentic. The VPN server will recognize clients that authenticate themselves by using a client certificate that was issued by the trusted CA.

This container assists to establish a PKI in your environment, if you do not have it yet. The internal CA is the ideal fit, if you want to get the VPN server up and running as fast and easy as possible. Optionally the container can be configured to use an external CA. This approach is something for people that either have an already running PKI or simply want to take direct control of security related operations.

#### Internal Certificate Authority

TODO

#### External Certificate Authority

TODO
