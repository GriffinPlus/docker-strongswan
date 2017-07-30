# UNDER DEVELOPMENT - ***DO NOT USE IN PRODUCTION***

---------------------------------------------------------------------------

# Docker Image with Openswan

[![Build Status](https://travis-ci.org/cloudycube/docker-openswan.svg?branch=master)](https://travis-ci.org/cloudycube/docker-openswan) [![Docker 
Pulls](https://img.shields.io/docker/pulls/cloudycube/openswan.svg)](https://hub.docker.com/r/cloudycube/openswan) [![Github 
Stars](https://img.shields.io/github/stars/cloudycube/docker-openswan.svg?label=github%20%E2%98%85)](https://github.com/cloudycube/docker-openswan) [![Github 
Stars](https://img.shields.io/github/contributors/cloudycube/docker-openswan.svg)](https://github.com/cloudycube/docker-openswan) [![Github 
Forks](https://img.shields.io/github/forks/cloudycube/docker-openswan.svg?label=github%20forks)](https://github.com/cloudycube/docker-openswan)

## Overview
This is a Docker image deriving from the [base-supervisor](https://github.com/cloudycube/docker-base-supervisor) image. It adds the popular VPN software [Openswan](https://www.openswan.org/) that allows you to create a VPN tunnel from any IPSec capable client right into your Docker stack. This can be useful, if you want to access your services remotely, but don't want your services (especially administration panels) to be visible on the public internet. This greatly reduces the attack vectors malicious people can use to gain access to your system.

This image belongs to a set of Docker images created for project [CloudyCube](https://www.falk-online.eu/projekte/cloudycube). The homepage is in German only, but you will find everything needed to get it working here as well.

## For Users

### Environment Variables

#### TODO
