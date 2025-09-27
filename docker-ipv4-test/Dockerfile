# Start with Windows Server Core as the base image
FROM mcr.microsoft.com/windows/server:ltsc2022

# Set metadata for the image
LABEL description="Windows container for IPv4 sACN testing"

# Download and install Build Tools for Visual Studio 2022 for native desktop workload.
# ADD https://aka.ms/vs/17/release/vs_buildtools.exe C:\\TEMP\\vs_buildtools.exe
# RUN C:\\TEMP\\vs_buildtools.exe --quiet --wait --norestart --nocache \
#     --channelUri C:\\TEMP\\VisualStudio.chman \
#     --installChannelUri C:\\TEMP\\VisualStudio.chman \
#     --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended \
#     --installPath C:\\BuildTools


# Set up environment variables for MSYS2 installation
RUN powershell -Command $env:MSYS2_PATH=\"C:\\msys64\\\"

# Install MSYS2
RUN powershell -Command \
    Invoke-WebRequest -Uri https://repo.msys2.org/distrib/x86_64/msys2-x86_64-20250830.exe -OutFile msys2-installer.exe; \
    Start-Process -FilePath msys2-installer.exe -ArgumentList '/S', '/D=$MSYS2_PATH' -Wait; \
    Remove-Item msys2-installer.exe

RUN powershell -Command $env:PATH=\"$env:MSYS2_PATH\\usr\\bin;$env:MSYS2_PATH\\mingw64\\bin;$env:PATH\"; \
    echo $env:PATH

# Update MSYS2 packages and install necessary tools (e.g., MinGW-w64 toolchain, git)
RUN powershell -Command $env:MSYS2_PATH\\usr\\bin\\bash.exe -lc "pacman -Syu --noconfirm && \
    pacman -S --noconfirm --needed base-devel mingw-w64-x86_64-toolchain git"

# Install Rust
RUN powershell -Command $env:RUSTUP_HOME=\"C:\\.rustup\\\"
RUN powershell -Command $env:CARGO_HOME=\"C:\\.cargo\\\"

# Install Rust using rustup
RUN powershell -Command \
    Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe; \
    Start-Process -Wait -FilePath .\rustup-init.exe -ArgumentList '-y', '--default-toolchain', 'stable', '--target', 'x86_64-pc-windows-gnu'; \
    Remove-Item rustup-init.exe; \
    echo $env:PATH

# Add Rust binaries to PATH
# ENV PATH="C:\\rust\\.cargo\\bin;${PATH}"
RUN powershell -Command $env:PATH=\"$env:CARGO_HOME\\.cargo\\bin;$env:PATH\"

RUN powershell -Command echo $env:PATH

# Set working directory to the root of the project
WORKDIR /app

# Copy project files
COPY src/ ./src/
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY tests/ ./tests/

# Install required PowerShell modules
# RUN powershell -Command \
    # Install-Module -Name NetAdapter -Force -SkipPublisherCheck; \
    # Install-Module -Name NetTCPIP -Force -SkipPublisherCheck

# Copy test scripts
COPY docker-ipv4-test/scripts/configure-ip.ps1 ./scripts/
COPY docker-ipv4-test/scripts/run-tests.ps1 ./scripts/
#COPY docker-ipv4-test/tests/ipv4_tests.ps1 ./tests/

# Make scripts executable
RUN powershell -Command \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    cargo build --verbose --target x86_64-pc-windows-gnu

# Set the entry point to PowerShell
ENTRYPOINT ["powershell.exe"]

# Default command to run tests via our script
CMD ["-File", ".\\docker-ipv4-test\\src\\scripts\\run-tests.ps1"]
