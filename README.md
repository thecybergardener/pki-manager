# pki-manager
A Bash-based Public Key Infrastructure (PKI) managment tool that helps setup and maintain SSL/TLS certs. This tool uses elliptic curve cryptography for certificates.

## Features

- Elliptic curve cryptography (ECC) support
- Root CA and Intermediate CA generation
- Service certificate generation and management
- Certificate expiration checking
- Automatic backup functionality
- Full & intermediate certificate chain creation
- Backup and offline root CA

## Prerequisites

- OpenSSL 1.1.1 or later (3.0.0 or later recommended)
- Bash 4.0 or later (5.1.16 or later recommended)
- Basic understanding of PKI concepts

## File Structure
```bash
├── pki-manager.sh        # Main PKI management script
├── config.env.example    # Template for configuration
└── openssl.conf.example   # Template for OpenSSL configuration
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/thecybergardener/pki-manager.git
cd pki-manager
```

2. Create your configuration:
```bash
cp config.env.example config.env
```

3. Make the script executable:
```bash
chmod u+x pki-manager.sh
```

## PKI Directory Structure

```
pki/
├── chains/          # Certificate chains
├── root/
│   ├── private/     # Root CA private key
│   ├── certs/       # Root CA certificate
│   ├── newcerts/    # Newly issued certificates
│   └── crl/         # Certificate revocation lists
├── intermediate/
│   ├── private/     # Intermediate CA private key
│   ├── certs/       # Intermediate CA certificate
│   ├── csr/         # Certificate signing requests
│   └── newcerts/    # Newly issued certificates
└── services/
    └── <service-name>/
        ├── private/ # Service private key
        ├── certs/   # Service certificate
        └── csr/     # Service CSR
```

## Configuration

Edit `config.env` to customize your PKI settings:

```bash
# Cryptographic settings
CURVE="prime256v1"  # Options: prime256v1, secp384r1, secp521r1

# Certificate validity periods (in days)
ROOT_VALIDITY=3560         # 10 years
INTERMEDIATE_VALIDITY=730  # 2 years
LEAF_VALIDITY=180          # 6 months
```

### Available Curves

- `prime256v1` (P-256): 128-bit security level, widely supported
- `secp384r1` (P-384): 192-bit security level, stronger security
- `secp521r1` (P-521): 256-bit security level, highest security

### Certificate Validity Peroids

Adjust the validity periods to your own preferences.

## Usage

### Initialize PKI Structure

Creates the PKI directory structure and generates root/intermediate CAs:
```bash
./pki-manager.sh init
```

### Generate Service Certificate

Creates a new certificate for a service:
```bash
./pki-manager.sh new-cert nginx example.com
```

### Check Certificate Expiration

Checks when all services certificate will expire:
```bash
./pki-manager.sh check 
```

Checks when a service's certificate will expire:
```bash
./pki-manager.sh check nginx
```

### Create Backup

Creates a backup of the PKI directory:
```bash
./pki-manager.sh backup
```

## Security Considerations

1. **Root CA Protection**
   - Keep the root CA offline when not in use
   - Store the root CA private key securely
   - Use the intermediate CA for day-to-day operations

2. **Private Keys**
   - All private keys are stored with 400 permissions (read-only for owner)
   - Private key directories have 700 permissions (accessible only by owner)

3. **Backups**
   - Regular backups are recommended
   - Backup private keys separately and securely
   - Keep backup media secure and offline

## Certificate Lifecycle Considerations

1. Monitor certificate expiration:
   - Script provides warnings 30 days before expiration
   - Plan renewals before expiration

## Best Practices

1. **Root CA Management**
   - Keep root CA offline when not in use
   - Use intermediate CA for routine operations
   - Secure root CA private key

2. **Service Certificates**
   - Use descriptive service names
   - Implement automatic renewal where possible
   - Monitor certificate expiration dates

3. **Backup Strategy**
   - Regular backups of the PKI directory
   - Secure storage of backup media
   - Test restore procedures periodically

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod 700 pki/root/private
   chmod 400 pki/root/private/ca.key
   ```

2. **Configuration Not Found**
   - Ensure `config.env` exists in the same directory as the script
   - Check file permissions

3. **OpenSSL Errors**
   - Verify OpenSSL installation
   - Check OpenSSL version compatibility
   - Validate openssl.conf syntax
   ```bash
   openssl req -config openssl.conf -test
   ```

## Future Planned Features

- Certificate Revocation
- Interactive init
- Dockerized Version
- Webserver to serve/download certificates

## License

This project is licensed under the MIT License - see the LICENSE file for details.
