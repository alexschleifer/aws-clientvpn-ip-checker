# AWS Lambda Function for Client VPN Geolocation

This project provides an AWS Lambda function designed to automate the geolocation detection of AWS Client VPN users. As part of a larger solution for enhancing security and compliance by analyzing the geolocation of VPN connections, this function fetches and returns city and country information for a given public IP address, utilizing the `https://ipinfo.io/` or other services. This approach aligns with the strategies discussed in [Automating the Detection of Geolocation of Client VPN Users](https://aws.amazon.com/blogs/media/cs-automate-detecting-geolocation-of-client-vpn-users-lambda-function/) on the AWS blog, and implements connection authorization based on geolocation as detailed in the [AWS Client VPN Administrator Guide](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/connection-authorization.html#connection-authorization-posture-assessment).

## Solution Overview

This Lambda function is a crucial component of a security posture assessment solution that enables AWS administrators to automatically authorize VPN connections based on the geolocation of the connecting user. By integrating this function into the AWS Client VPN endpoint's connection authorization process, administrators can enforce geolocation-based access policies, thus enhancing the security and compliance of their AWS environments.

## Features

- **Automated Geolocation Detection**: Extracts the public IP from VPN connection requests and retrieves the corresponding city and country information.
- **Flexible Integration**: Designed to be integrated with AWS Client VPN's connection authorization feature, enabling dynamic access control based on geolocation.
- **Secure and Scalable**: Leverages AWS Lambda for a serverless implementation, ensuring scalability and reducing operational overhead.

## Prerequisites

- An AWS account with permissions to create Lambda functions and manage Client VPN endpoints.
- Rust and Cargo installed on your development machine for compiling the function.
- Basic familiarity with AWS Lambda and Client VPN's connection authorization process.

## Deployment

### Compile the Rust Project

Ensure the project is compiled for the `x86_64-unknown-linux-musl` target to guarantee compatibility with AWS Lambda's execution environment.

```bash
cargo lambda build --release

### Delpoy the Rust Project to lambda

```bash
cargo lambda deploy --profile <profile name>

## Integrate with Client VPN
Follow the guidelines provided in the AWS Client VPN Administrator Guide to integrate the Lambda function with your Client VPN endpoint. [AWS Client VPN Administrator Guide](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/connection-authorization.html#connection-authorization-posture-assessment). You will need to configure the Client VPN endpoint to invoke this Lambda function for connection authorization based on geolocation.

## Usage
The Lambda function is triggered by connection attempts to the AWS Client VPN endpoint. It automatically extracts the public IP address from the connection request and queries IP geolocation db service for geolocation data, which is then used to authorize or deny the connection based on your configured policies.