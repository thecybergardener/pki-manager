#!/bin/bash
#
# PKI Management Script
# This script manages a Public Key Infrastructure (PKI) using elliptic curve cryptography
# 
# Features:
# - Root CA and Intermediate CA generation
# - Service certificate generation
# - Certificate expiration checking
# - Automatic backup of critical files
#
# Usage: ./pki-manager.sh {init|offline-root|new-cert|check|backup} [options]

set -euo pipefail   # error handling options

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load configuration
CONFIG_FILE="${SCRIPT_DIR}/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found at $CONFIG_FILE"
    echo "Please copy config.env.example to config.env and modify as needed"
    exit 1
fi

source "$CONFIG_FILE"

# Set cert, key and csr paths
ROOT_KEY="${ROOT_DIR}/root/private/ca.key"
ROOT_CERT="${ROOT_DIR}/root/certs/ca.crt"
INTERMEDIATE_KEY="${ROOT_DIR}/intermediate/private/intermediate.key"
INTERMEDIATE_CERT="${ROOT_DIR}/intermediate/certs/intermediate.crt"
INTERMEDIATE_CSR="${ROOT_DIR}/intermediate/csr/intermediate.csr"

# Logging function
log() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo "${message}"
    echo "${message}" >> "${LOG_FILE}"
}

error() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "\e[31m${message}\e[0m" >&2 # Print to console in red
    echo "${message}" >> "${LOG_FILE}"
    exit 1
}

# Function to validate configuration
validate_config() {
    local required_vars=(
        "CURVE" "ROOT_VALIDITY" "INTERMEDIATE_VALIDITY" "LEAF_VALIDITY"
        "ROOT_DIR" "OPENSSL_CNF" "COUNTRY" "STATE" "LOCALITY"
        "ORGANIZATION" "ROOT_CN" "INTERMEDIATE_CN" "LOG_FILE"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error "Required configuration variable $var is not set"
        fi
    done

    if [[ ! -f "$OPENSSL_CNF" ]]; then
        error "OpenSSL configuration file not found at $OPENSSL_CNF"
    fi
}

# Function to take root CA offline (backup and remove)
offline_root_ca() {
    local backup_path="$1"
    local org_name=$(echo "${ORGANIZATION}" | tr '[:upper:] ' '[:lower:]-')
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local root_backup_dir="${backup_path}/${org_name}-root-ca-backup-${timestamp}"

    # Verify backup path exists
    if [[ ! -d "$backup_path" ]]; then
        error "Backup destination ${backup_path} does not exist"
    fi

    # Verify root key exists
    if [[ ! -f "${ROOT_KEY}" ]]; then
        error "Root CA key not found at ${ROOT_KEY}"
    fi

    log "Taking Root CA offline - this will backup and remove the root key"
    read -p "Are you sure you want to proceed? (yes/no) " answer
    if [[ "${answer,,}" != "yes" ]]; then
        log "Operation cancelled"
        exit 1
    fi

    # Create backup directory
    mkdir -p "${root_backup_dir}"
    chmod 700 "${root_backup_dir}"

    log "Creating Root CA backup at: ${root_backup_dir}"

    # Backup files with original permissions
    cp -p "${ROOT_KEY}" "${root_backup_dir}/${org_name}-root-ca.key"
    cp -p "${ROOT_CERT}" "${root_backup_dir}/${org_name}-root-ca.crt"
    cp -p "${ROOT_DIR}/root/index.txt" "${root_backup_dir}/index.txt"
    cp -p "${ROOT_DIR}/root/serial" "${root_backup_dir}/serial"

    # Create checksums
    (cd "${root_backup_dir}" && sha256sum * > sha256sums.txt)

    # Create tar archive
    tar czf "${root_backup_dir}.tar.gz" -C "$(dirname ${root_backup_dir})" "$(basename ${root_backup_dir})"
    chmod 600 "${root_backup_dir}.tar.gz"

    # Clean up uncompressed directory
    rm -rf "${root_backup_dir}"

    log "Root CA backup created: ${root_backup_dir}.tar.gz"

    # Remove the root key using shred
    log "Proceeding to remove Root CA private key..."
    shred -u "${ROOT_KEY}"

    if [[ -f "${ROOT_KEY}" ]]; then
        error "Failed to remove Root CA key!"
    fi

    log "Root CA has been taken offline successfully"
    log "IMPORTANT NEXT STEPS:"
    log "1. Copy ${root_backup_dir}.tar.gz to encrypted USB drive"
    log "2. Store in secure physical location"
    log "3. Create multiple backup copies"
    log "4. Document backup location securely"
    log "5. Verify your backup before deleting from this location"
}

create_cert_chain() {
    log "Creating certificate chain file"
    
    # Create chains directory if it doesn't exist
    mkdir -p "${ROOT_DIR}/chains"
    
    # Format organization name for filename (lowercase, replace spaces with hyphens)
    local org_name=$(echo "${ORGANIZATION}" | tr '[:upper:] ' '[:lower:]-')
    
    # Create full chain (root + intermediate)
    cat "${INTERMEDIATE_CERT}" "${ROOT_CERT}" > "${ROOT_DIR}/chains/${org_name}-ca-chain.crt"
    chmod 644 "${ROOT_DIR}/chains/${org_name}-ca-chain.crt"
    
    # Create intermediate chain (just intermediate)
    cp "${INTERMEDIATE_CERT}" "${ROOT_DIR}/chains/${org_name}-intermediate-chain.crt"
    chmod 644 "${ROOT_DIR}/chains/${org_name}-intermediate-chain.crt"
    
    log "Certificate chains created at:"
    log "  Full chain (root + intermediate): ${ROOT_DIR}/chains/${org_name}-ca-chain.crt"
    log "  Intermediate chain: ${ROOT_DIR}/chains/${org_name}-intermediate-chain.crt"
}

create_service_chain() {
    local SERVICE="$1"
    log "Creating certificate chain file for service ${SERVICE}"
    
    # Create service chains directory if it doesn't exist
    mkdir -p "${ROOT_DIR}/services/${SERVICE}/chains"
    
    # Create service chain (service + intermediate)
    cat "${ROOT_DIR}/services/${SERVICE}/certs/${SERVICE}.crt" "${INTERMEDIATE_CERT}" > \
        "${ROOT_DIR}/services/${SERVICE}/chains/${SERVICE}-chain.crt"
    chmod 644 "${ROOT_DIR}/services/${SERVICE}/chains/${SERVICE}-chain.crt"
    
    log "Service certificate chain created at: ${ROOT_DIR}/services/${SERVICE}/chains/${SERVICE}-chain.crt"
}

# Function to check if PKI structure exists
check_existing_pki() {
    if [[ -d "${ROOT_DIR}" ]]; then
        log "Warning: PKI directory '${ROOT_DIR}' already exists"
        read -p "Do you want to continue? This will backup the existing directory, then remove it. (y/N) " -n 1 -r
        echo    # New line
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error "Aborted by user"
        fi
        
        # Backup existing structure if user wants to proceed
        if [[ "$BACKUP_ENABLED" == "true" ]]; then
            log "Creating backup of existing PKI structure"
            backup_pki
            log "Removing existing PKI structure"
            rm -rf "${SCRIPT_DIR}/${ROOT_DIR}"

            # Verify removal
            if [[ -d "${SCRIPT_DIR}/${ROOT_DIR}" ]]; then
                error "Failed to remove directory"
                return 1
            fi
            
            log "Directory removed successfully"
            return 0
        fi
    fi
}

# Function to create directory structure
create_directory_structure() {
    check_existing_pki
    log "Creating PKI directory structure"
    mkdir -p ${ROOT_DIR}/{root,intermediate}/{private,certs,csr,newcerts,crl}
    chmod 700 ${ROOT_DIR}/{root,intermediate}/private
    
    for dir in root intermediate; do
        [[ -f "${ROOT_DIR}/${dir}/index.txt" ]] || touch "${ROOT_DIR}/${dir}/index.txt"
        [[ -f "${ROOT_DIR}/${dir}/serial" ]] || echo 1000 > "${ROOT_DIR}/${dir}/serial"
    done
}

# Function to backup critical files
backup_pki() {
    if [[ "$BACKUP_ENABLED" != "true" ]]; then
        log "Backups are disabled in configuration"
        return 0
    fi

    local backup_date=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/pki_backup_${backup_date}.tar.gz"
    
    log "Creating backup at ${backup_file}"
    mkdir -p "$BACKUP_DIR"
    
    # Backup everything except private keys
    tar -czf "$backup_file" \
        --exclude "${ROOT_DIR}/*/private" \
        "$ROOT_DIR"
    
    log "Backup completed successfully"
}

# Function to generate root CA
generate_root_ca() {
    log "Generating root CA key using ${CURVE} curve"
    openssl ecparam -genkey -name ${CURVE} -out ${ROOT_KEY}
    chmod 400 ${ROOT_KEY}

    log "Generating root CA certificate (valid for ${ROOT_VALIDITY} days)"
    openssl req -config ${OPENSSL_CNF} -key ${ROOT_KEY} -new -x509 -days ${ROOT_VALIDITY} \
        -sha384 -extensions v3_ca -out ${ROOT_CERT} \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${ROOT_CN}"
}

# Function to generate intermediate CA
generate_intermediate_ca() {
    log "Generating intermediate CA key using ${CURVE} curve"
    openssl ecparam -genkey -name ${CURVE} -out ${INTERMEDIATE_KEY}
    chmod 400 ${INTERMEDIATE_KEY}

    log "Generating intermediate CA CSR"
    openssl req -config ${OPENSSL_CNF} -new -sha384 \
        -key ${INTERMEDIATE_KEY} -out ${INTERMEDIATE_CSR} \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${INTERMEDIATE_CN}"

    log "Signing intermediate CA certificate (valid for ${INTERMEDIATE_VALIDITY} days)"
    openssl ca -config ${OPENSSL_CNF} -name root_ca -extensions v3_intermediate_ca \
        -days ${INTERMEDIATE_VALIDITY} -notext -md sha384 \
        -in ${INTERMEDIATE_CSR} -out ${INTERMEDIATE_CERT}
}

# Function to format Subject Alternative Names
format_san() {
    local domain="$1"
    shift
    local sans=("$@")
    local san_string="DNS:${domain}"  # Primary domain always included
    
    for name in "${sans[@]}"; do
        if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # IP address
            san_string+=",IP:${name}"
        else
            # DNS name
            san_string+=",DNS:${name}"
        fi
    done
    
    echo "$san_string"
}

# Function to create temporary OpenSSL config with SANs
create_temp_config() {
    local temp_conf="${ROOT_DIR}/temp_openssl.conf"
    local san_string="$1"
    
    # Copy the main config
    cp "${OPENSSL_CNF}" "${temp_conf}"
    
    # Replace the SAN variable with actual values
    if [[ -n "${san_string}" ]]; then
        # Add the SAN section with actual values
        echo "" >> "${temp_conf}"
        echo "[ server_san_cert ]" >> "${temp_conf}"
        echo "basicConstraints = CA:FALSE" >> "${temp_conf}"
        echo "nsCertType = server" >> "${temp_conf}"
        echo "nsComment = \"OpenSSL Generated Server Certificate\"" >> "${temp_conf}"
        echo "subjectKeyIdentifier = hash" >> "${temp_conf}"
        echo "authorityKeyIdentifier = keyid,issuer:always" >> "${temp_conf}"
        echo "keyUsage = critical, digitalSignature, keyEncipherment" >> "${temp_conf}"
        echo "extendedKeyUsage = serverAuth" >> "${temp_conf}"
        echo "subjectAltName = ${san_string}" >> "${temp_conf}"
    fi
    
    echo "${temp_conf}"
}

# Function to sign an existing CSR
sign_csr() {
    local CSR_PATH="$1"
    local SERVICE="$2"
    shift 2
    local ALTERNATE_NAMES=("$@")
    
    log "Signing CSR from ${CSR_PATH} for service ${SERVICE}"
    
    # Verify CSR exists
    if [[ ! -f "${CSR_PATH}" ]]; then
        error "CSR file not found at ${CSR_PATH}"
    fi
    
    # Create service directories if they don't exist
    mkdir -p "${ROOT_DIR}/services/${SERVICE}/certs"
    
    # Format SAN string if alternate names provided
    if [[ ${#ALTERNATE_NAMES[@]} -gt 0 ]]; then
        # Extract CN from CSR to use as primary domain
        primary_domain=$(openssl req -in "${CSR_PATH}" -noout -subject | sed -n 's/.*CN\s*=\s*\([^,]*\).*/\1/p')
        local san_string=$(format_san "$primary_domain" "${ALTERNATE_NAMES[@]}")
        log "Adding Subject Alternative Names: ${san_string}"
        
        # Create temporary config with SANs
        local temp_conf=$(create_temp_config "${san_string}")
        
        # Sign the CSR with SANs
        openssl ca -config "${temp_conf}" -name intermediate_ca -extensions server_san_cert \
            -days ${LEAF_VALIDITY} -notext -md sha384 \
            -in "${CSR_PATH}" \
            -out "${ROOT_DIR}/services/${SERVICE}/certs/${SERVICE}.crt"
            
        # Clean up
        rm -f "${temp_conf}"
    else
        # Sign without SANs
        openssl ca -config ${OPENSSL_CNF} -name intermediate_ca -extensions server_cert \
            -days ${LEAF_VALIDITY} -notext -md sha384 \
            -in "${CSR_PATH}" \
            -out "${ROOT_DIR}/services/${SERVICE}/certs/${SERVICE}.crt"
    fi
    
    log "Certificate generated successfully for ${SERVICE} from provided CSR"
}

# Function to generate leaf certificate
generate_leaf_cert() {
    local SERVICE="$1"
    local DOMAIN="$2"
    local CSR_PATH="${3:-}"  # Optional CSR path
    shift 3
    local ALTERNATE_NAMES=("$@")  # All remaining arguments are alternate names
    
    if [[ -n "${CSR_PATH}" ]]; then
        # Use provided CSR
        sign_csr "${CSR_PATH}" "${SERVICE}" "${ALTERNATE_NAMES[@]}"
    else
        # Generate new key and CSR
        log "Generating new key and CSR for ${SERVICE} (${DOMAIN})"
        
        mkdir -p ${ROOT_DIR}/services/${SERVICE}/{private,certs,csr}
        
        # Generate private key
        openssl ecparam -genkey -name ${CURVE} \
            -out "${ROOT_DIR}/services/${SERVICE}/private/${SERVICE}.key"
        chmod 400 "${ROOT_DIR}/services/${SERVICE}/private/${SERVICE}.key"
        
        # Generate CSR
        openssl req -config ${OPENSSL_CNF} -new -sha384 \
            -key "${ROOT_DIR}/services/${SERVICE}/private/${SERVICE}.key" \
            -out "${ROOT_DIR}/services/${SERVICE}/csr/${SERVICE}.csr" \
            -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${DOMAIN}"
        
        # Sign certificate with appropriate extensions
        if [[ ${#ALTERNATE_NAMES[@]} -gt 0 ]]; then
            local san_string=$(format_san "$DOMAIN" "${ALTERNATE_NAMES[@]}")
            log "Adding Subject Alternative Names: ${san_string}"
            
            # Create temporary config with SANs
            local temp_conf=$(create_temp_config "${san_string}")
            
            openssl ca -config "${temp_conf}" -name intermediate_ca -extensions server_san_cert \
                -days ${LEAF_VALIDITY} -notext -md sha384 \
                -in "${ROOT_DIR}/services/${SERVICE}/csr/${SERVICE}.csr" \
                -out "${ROOT_DIR}/services/${SERVICE}/certs/${SERVICE}.crt"
                
            # Clean up
            rm -f "${temp_conf}"
        else
            openssl ca -config ${OPENSSL_CNF} -name intermediate_ca -extensions server_cert \
                -days ${LEAF_VALIDITY} -notext -md sha384 \
                -in "${ROOT_DIR}/services/${SERVICE}/csr/${SERVICE}.csr" \
                -out "${ROOT_DIR}/services/${SERVICE}/certs/${SERVICE}.crt"
        fi
        
        # Create the service certificate chain
        create_service_chain "${SERVICE}"
        log "Certificate and chain generated successfully for ${SERVICE}"
    fi
}

# Function to list all services
list_services() {
    local services_dir="${ROOT_DIR}/services"
    if [[ ! -d "$services_dir" ]]; then
        echo "No services found."
        echo "Please run $(basename "$0") new-cert"
        return 1
    fi
    
    local services=()
    while IFS= read -r -d '' dir; do
        services+=($(basename "$dir"))
    done < <(find "$services_dir" -mindepth 1 -maxdepth 1 -type d -print0)
    
    if [[ ${#services[@]} -eq 0 ]]; then
        echo "No services found"
        return 1
    fi
    
    log "Found ${#services[@]} service(s):"
    for service in "${services[@]}"; do
        check_expiration "${services_dir}/${service}/certs/${service}.crt" "${service}"
    done
}
# Function to check certificate expiration
check_expiration() {
    local CERT_PATH=$1
    local SERVICE=$2
    
    if [[ ! -f "$CERT_PATH" ]]; then
        error "Certificate not found at ${CERT_PATH}"
    fi
    
    expiry_date=$(openssl x509 -enddate -noout -in ${CERT_PATH} | cut -d= -f2)
    expiry_epoch=$(date -d "${expiry_date}" +%s)
    current_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    log "${SERVICE} certificate expires in ${days_left} days"
    
    if [ ${days_left} -lt 30 ]; then
        echo "WARNING: Certificate for ${SERVICE} will expire soon!"
    fi
}

# Display help message
show_help() {
    cat << EOF
PKI Management Script

Usage: $(basename "$0") COMMAND [OPTIONS]

Commands:
    init                                                        Initialize PKI directory structure and create root/intermediate CAs
    offline-root PATH                                           Creates backup of root CA and deletes private key from disk
    new-cert SERVICE DOMAIN [CSR-FILE] [ALTERNATE-NAMES...]     Generate a new certificate for a service, optionally from existing CSR
    check                                                       Prints list of all available services
    check SERVICE                                               Check certificate expiration for a service
    backup                                                      Create a backup of the PKI directory
    help                                                        Show this help message

Options:
    SERVICE              Name of the service (e.g., nginx, apache)
    DOMAIN               Domain name for the certificate
    CSR-FILE             Certificate Service Request file path
    ALTERNATE-NAMES      Additional DNS names or IP addresses for the certificate


Examples:
    $(basename "$0") init
    $(basename "$0") offline-root /path/to/backup/
    $(basename "$0") new-cert nginx example.com
    $(basename "$0") new-cert nginx example.com /path/to/nginx.csr
    $(basename "$0") new-cert nginx example.com 192.168.1.10 server2.local
    $(basename "$0") new-cert nginx example.com nginx.csr 192.168.1.10 server2.local
    $(basename "$0") check
    $(basename "$0") check nginx
    $(basename "$0") backup

Configuration:
    The script reads its configuration from config.env in the same directory.
    Copy config.env.example to config.env and modify as needed.
EOF
}

# Validate configuration before proceeding
validate_config

# Check if an argument was provided
if [[ $# -eq 0 ]]; then
    show_help
    exit 1
fi

# Main execution starts here
case "$1" in
    "init")
        create_directory_structure
        generate_root_ca
        generate_intermediate_ca
        create_cert_chain
        [[ "$BACKUP_ENABLED" == "true" ]] && backup_pki

        log "PKI initialization complete. Important files:"
        log "  Root CA: ${ROOT_CERT}"
        log "  Intermediate CA: ${INTERMEDIATE_CERT}"
        log "  Full Chain: ${ROOT_DIR}/chains/ca-chain.crt"
        log "  Intermediate Chain: ${ROOT_DIR}/chains/intermediate-chain.crt"
        ;;
    "offline-root")
        if [ -z "${2:-}" ]; then
            error "Usage: $0 offline-root <backup-destination-path>"
        fi
        offline_root_ca "$2"
        ;;    
    "new-cert")
        if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
            error "Usage: $0 new-cert <service-name> <domain> [csr-file] [alternate-name1 alternate-name2 ...]"
        fi
        SERVICE="$2"
        DOMAIN="$3"
        shift 3  # Remove command, service, and domain from arguments
        
        # Check if next argument is a CSR file
        if [[ -n "${1:-}" && -f "$1" && "$1" == *.csr ]]; then
            CSR_PATH="$1"
            shift  # Remove CSR path from arguments
        else
            CSR_PATH=""
        fi
        
        # Remaining arguments are alternate names
        generate_leaf_cert "$SERVICE" "$DOMAIN" "$CSR_PATH" "$@"
        [[ "$BACKUP_ENABLED" == "true" ]] && backup_pki
        ;;
    "check")
        if [ -z "${2:-}" ]; then
            list_services
            # error "Usage: $0 check <service-name>"
            exit 1
        fi
        check_expiration "${ROOT_DIR}/services/$2/certs/$2.crt" "$2"
        ;;
    "backup")
        backup_pki
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        error "Unknown command: $1\nUse '$(basename "$0") help' for usage information"
        ;;
esac
