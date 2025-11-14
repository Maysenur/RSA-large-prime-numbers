# Base image
FROM ubuntu:22.04

# Non-interactive apt
ENV DEBIAN_FRONTEND=noninteractive

# Install C++ tools, OpenCV, Python
RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    make \
    pkg-config \
    git \
    wget \
    libssl-dev \
    libopencv-dev \
    libgtk2.0-dev \
    libcanberra-gtk-module \
    libcanberra-gtk3-module \
    python3-pip \
    nano \
    hyperfine \
    libgmp-dev \
    libmpfr-dev \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir matplotlib numpy jupyter opencv-python

# Download cxxopts library
RUN git clone --branch v3.3.1 --depth 1 https://github.com/jarro2783/cxxopts.git /root/cpp-libs/cxxopts

# Working directory
WORKDIR /RSA_large_prime_numbers
COPY . /RSA_large_prime_numbers

EXPOSE 8888

# Default command: bash
CMD ["/bin/bash"]