FROM cloudycube/base-supervisor
MAINTAINER Sascha Falk <sascha@falk-online.eu>

# Update image and install additional packages
# -----------------------------------------------------------------------------
RUN apt-get -y update && \
  apt-get -y install \
    iptables \
    module-init-tools \
    strongswan && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

# Copy prepared files into the image
# -----------------------------------------------------------------------------
COPY target /

# Volumes
# -----------------------------------------------------------------------------
VOLUME [ "/etc/ipsec.d" ]

# Expose ports
# -----------------------------------------------------------------------------
# 500/udp  - Internet Key Exchange (IKE)
# 4500/udp - NAT Traversal
# -----------------------------------------------------------------------------
EXPOSE 500 4500 
