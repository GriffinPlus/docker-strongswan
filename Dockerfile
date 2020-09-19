FROM griffinplus/base-supervisor
MAINTAINER Sascha Falk <sascha@falk-online.eu>

ENV STRONGSWAN_VERSION="5.9.0"

# Update image and install additional packages
# -----------------------------------------------------------------------------
RUN \
  # install packages
  DEV_PACKAGES="bzip2 make gcc libcurl4-openssl-dev libgmp-dev libssl-dev" && \
  apt-get -y update && \
  apt-get -y install \
    bind9 \
    libcurl4 libgmp10 libssl1.0.0 \
    module-init-tools \
    $DEV_PACKAGES && \
  \
  # download and build strongswan source code
  mkdir /strongswan-build && \
  cd /strongswan-build && \
  wget https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
  tar -xjf strongswan-$STRONGSWAN_VERSION.tar.bz2 && \
  cd strongswan-$STRONGSWAN_VERSION && \
  ./configure --prefix=/usr --sysconfdir=/etc --enable-aesni --enable-af-alg --enable-ccm --enable-curl --enable-eap-dynamic --enable-eap-identity --enable-eap-tls --enable-files --enable-gcm --enable-openssl && \
  make all && make install && \
  cd / && rm -R /strongswan-build && \
  \
  # clean up
  apt-get -y remove $DEV_PACKAGES && \
  apt-get -y autoremove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

# Copy prepared files into the image
# -----------------------------------------------------------------------------
COPY target /

# Adjust permissions of copied files
# -----------------------------------------------------------------------------
RUN chmod 750 /etc/strongswan-updown.sh

# Volumes
# -----------------------------------------------------------------------------
VOLUME [ "/data" ]

# Expose ports
# -----------------------------------------------------------------------------
# 500/udp  - Internet Key Exchange (IKE)
# 4500/udp - NAT Traversal
# -----------------------------------------------------------------------------
EXPOSE 500 4500

