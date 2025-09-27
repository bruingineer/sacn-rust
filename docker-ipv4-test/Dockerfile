# Start with Windows Server Core as the base image
FROM mcr.microsoft.com/windows/server:ltsc2022

# Set metadata for the image
LABEL description="Windows container for IPv4 sACN testing"

# Set working directory to the root of the project
WORKDIR /app


RUN powershell -Command $env:RUSTUP_HOME=\"C:\.rustup\\"
RUN powershell -Command $env:CARGO_HOME=\"C:\.cargo\\"

# Install Rust using rustup
RUN powershell -Command \
    Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe; \
    Start-Process -Wait -FilePath .\rustup-init.exe -ArgumentList '-y'; \
    Remove-Item rustup-init.exe; \
    echo $env:PATH

# Add Rust binaries to PATH
# ENV PATH="C:\\rust\\.cargo\\bin;${PATH}"
RUN powershell -Command $env:PATH=\"$env:CARGO_HOME\\.cargo\\bin;$env:PATH\"

RUN powershell -Command echo $env:PATH

# Copy project files
COPY src/ ./src/
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY tests/ ./tests/

# Install required PowerShell modules
RUN powershell -Command \
    Install-Module -Name NetAdapter -Force -SkipPublisherCheck; \
    Install-Module -Name NetTCPIP -Force -SkipPublisherCheck

# Copy test scripts
COPY scripts/configure-ip.ps1 ./scripts/
COPY scripts/run-tests.ps1 ./scripts/
COPY tests/ipv4_tests.ps1 ./tests/

# Make scripts executable
RUN powershell -Command \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    cargo build --verbose

# Set the entry point to PowerShell
ENTRYPOINT ["powershell.exe"]

# Default command to run tests via our script
CMD ["-File", ".\\docker-ipv4-test\\src\\scripts\\run-tests.ps1"]
