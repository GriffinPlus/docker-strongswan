FROM cloudycube/base-supervisor
MAINTAINER Sascha Falk <sascha@falk-online.eu>

# Update image and install additional packages
# -----------------------------------------------------------------------------
RUN apt-get -y update && \
  apt-get -y install \
    iptables \
    module-init-tools \
    strongswan \
    strongswan-plugin-af-alg \
    strongswan-plugin-agent \
    strongswan-plugin-certexpire \
    strongswan-plugin-coupling \
    strongswan-plugin-curl \
    strongswan-plugin-dhcp \
    strongswan-plugin-duplicheck \
    strongswan-plugin-eap-aka \
    strongswan-plugin-eap-aka-3gpp2 \
    strongswan-plugin-eap-dynamic \
    strongswan-plugin-eap-gtc \
    strongswan-plugin-eap-mschapv2 \
    strongswan-plugin-eap-peap \
    strongswan-plugin-eap-radius \
    strongswan-plugin-eap-tls \
    strongswan-plugin-eap-ttls \
    strongswan-plugin-error-notify \
    strongswan-plugin-farp \
    strongswan-plugin-fips-prf \
    strongswan-plugin-gcrypt \
    strongswan-plugin-gmp \
    strongswan-plugin-ipseckey \
    strongswan-plugin-kernel-libipsec \
    strongswan-plugin-ldap \
    strongswan-plugin-led \
    strongswan-plugin-load-tester \
    strongswan-plugin-lookip \
    strongswan-plugin-ntru \
    strongswan-plugin-pgp \
    strongswan-plugin-pkcs11 \
    strongswan-plugin-pubkey \
    strongswan-plugin-radattr \
    strongswan-plugin-sshkey \
    strongswan-plugin-systime-fix \
    strongswan-plugin-whitelist \
    strongswan-plugin-xauth-eap \
    strongswan-plugin-xauth-generic \
    strongswan-plugin-xauth-noauth \
    strongswan-plugin-xauth-pam && \
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
