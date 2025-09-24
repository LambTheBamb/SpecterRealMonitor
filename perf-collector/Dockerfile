FROM debian:12

# Install required packages
RUN apt-get update && apt-get install -y \
#    linux-tools-5.19.0-46-generic \
#    linux-tools-generic \
#    linux-tools-common \
	linux-perf \
    python3 \
    python3-pip \
    curl \
    wget \
    build-essential \
    git \
    cmake \
    libpfm4-dev \
    libelf1 \
    libdw1 \
    libnuma1 \
    libunwind8 \
    libslang2 \
    libaudit1 \
    libcap-ng0 \
    zlib1g \
    libtraceevent1 \
    && rm -rf /var/lib/apt/lists/*
# Install Python dependencies
RUN pip3 install --break-system-packages \
    influxdb-client \
    psutil \
    numpy \
    scipy \
    requests \
    prometheus-client

# Install PAPI (Performance Application Programming Interface)
RUN cd /tmp && \
    wget http://icl.utk.edu/projects/papi/downloads/papi-7.0.1.tar.gz && \
    tar -xzf papi-7.0.1.tar.gz && \
    cd papi-7.0.1/src && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Install Intel PCM (if on Intel hardware)
RUN cd /tmp && \
    git clone https://github.com/intel/pcm.git && \
    cd pcm && \
    make && \
    cp pcm*.x /usr/local/bin/ || true

# Create working directory
WORKDIR /app

# Copy collector scripts
COPY collector.py /app/
COPY metrics_config.json /app/
COPY entrypoint.sh /app/
COPY baseline_calculator.py /app/
COPY anomaly_detector.py /app/
# Add to your /home/specter-monitor/perf-collector/Dockerfile
COPY enhanced_cloud_monitor.py /app/
COPY requirements.txt /app/
COPY perfomance-collector.py /app/
# Install additional Python packages if needed
RUN pip  install --break-system-packages  psutil pyinotify
# Make scripts executable
RUN chmod +x /app/entrypoint.sh

# Set up perf for container use
RUN echo 'kernel.perf_event_paranoid = -1' >> /etc/sysctl.conf
RUN echo 'kernel.kptr_restrict = 0' >> /etc/sysctl.conf

ENTRYPOINT ["/app/entrypoint.sh"]
