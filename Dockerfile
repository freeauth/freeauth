FROM ubuntu:22.04

# Set the working directory to /freeauth
WORKDIR /freeauth

# Copy all contents from the current directory to /freeauth
COPY . /freeauth

# Install necessary dependencies and clean up apt cache to reduce image size
RUN apt-get update && apt-get install -y \
    cmake make gcc g++ rustc cargo golang git libssl-dev time psmisc iproute2 iperf3 \
    && apt clean

# Ensure scripts have executable permissions
RUN chmod +x ./build.sh ./run.sh

# Run build.sh
RUN ./build.sh

# Run run.sh
CMD /bin/bash
