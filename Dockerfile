FROM cloudycube/base-supervisor
MAINTAINER Sascha Falk <sascha@falk-online.eu>

# Update image and install additional packages
# -----------------------------------------------------------------------------
RUN apt-get -y update && \
  apt-get -y install \
    bind9 \
    ndppd \
    strongswan \
    strongswan-plugin-af-alg \
    strongswan-plugin-eap-dynamic \
    strongswan-plugin-eap-tls \
    strongswan-plugin-eap-ttls \
    strongswan-plugin-kernel-libipsec \
    strongswan-plugin-whitelist && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

# Copy prepared files into the image
# -----------------------------------------------------------------------------
COPY target /

# Volumes
# -----------------------------------------------------------------------------
VOLUME [ "/data" ]

# Expose ports
# -----------------------------------------------------------------------------
# 500/udp  - Internet Key Exchange (IKE)
# 4500/udp - NAT Traversal
# -----------------------------------------------------------------------------
EXPOSE 500 4500 
