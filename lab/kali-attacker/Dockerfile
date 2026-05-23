FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    iputils-ping \
    curl \
    wget \
    net-tools \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
CMD ["/bin/bash"]
