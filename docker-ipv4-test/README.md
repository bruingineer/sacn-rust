# Docker IPv4 Test Project

This project provides a Docker container setup for running IPv4 tests on a Windows operating system. It includes scripts for configuring the IP address of the Ethernet adapter within the container and running the defined tests.

## Project Structure

- `src/scripts/configure-ip.ps1`: PowerShell script to configure the IP address of the Ethernet adapter.
- `src/scripts/run-tests.ps1`: PowerShell script to execute the IPv4 tests.
- `src/tests/ipv4_tests.ps1`: Contains the actual tests for IPv4 functionality.
- `.dockerignore`: Specifies files and directories to ignore when building the Docker image.
- `Dockerfile`: Instructions for building the Docker image.

## Setup Instructions

1. Ensure you have Docker installed on your Windows machine.
2. Clone this repository to your local machine.
3. Navigate to the project directory.
4. Build the Docker image using the following command:
   ```
   docker build -t ipv4-test .
   ```
5. Run the Docker container:
   ```
   docker run --rm -it ipv4-test
   ```

## Usage Guidelines

- Use `configure-ip.ps1` to set the desired IP address for the Ethernet adapter.
- Execute `run-tests.ps1` to run the IPv4 tests defined in the project.
- Review the output of the tests to verify IPv4 functionality.

## License

This project is licensed under the MIT License. See the LICENSE file for details.