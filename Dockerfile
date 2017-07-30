FROM cloudycube/base-supervisor
MAINTAINER Sascha Falk <sascha@falk-online.eu>

# Update image and install additional packages
RUN apt-get -y update && \
  apt-get -y install strongswan && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

# Copy prepared files into the image
COPY target /

