# AlmaLinux cloud images SBOM tools

Utility tools to help in the process of generating SBOM (Software Bill of Materials) documents for AlmaLinux cloud images and other Linux distributions based on Fedora.

## Overview

This toolkit provides a complete solution for collecting system metadata and generating SPDX-compliant SBOM documents from AlmaLinux and Fedora-based systems. The generated SBOMs include detailed package information, license data, and file relationships.

## Features

- **System metadata collection** from installed RPM packages
- **SPDX 2.3 compliant** SBOM generation
- **License mapping** from Fedora license names to SPDX identifiers
- **Package checksum collection** from repository metadata
- **CPE and PURL** external references for security and package management
- **File-level tracking** within packages
- **Comprehensive logging** and debugging support

## Scripts

### 1. `sbom_data_collector.py`

Collects comprehensive metadata from the system's installed packages using DNF/YUM.

**Features:**
- Extracts package information (name, version, release, architecture, etc.)
- Collects license, vendor, and source RPM information
- Optionally retrieves package checksums from repository metadata
- Outputs structured JSON metadata

**Usage:**
```bash
python sbom_data_collector.py -o metadata.json [-wc] [-v]
```

**Options:**
- `-o, --output`: Output JSON file (required)
- `-wc, --with-checksums`: Collect available checksums from repository data
- `-v, --verbose`: Enable verbose output

### 2. `sbom_generator.py`

Generates SPDX 2.3 compliant SBOM documents from collected metadata.

**Features:**
- Creates SPDX JSON format SBOM documents
- Generates unique SPDX IDs for packages and files
- Includes external references (CPE and PURL)
- Establishes package-file relationships
- Optional SBOM validation

**Usage:**
```bash
python sbom_generator.py <name> <metadata> <output> [--validate]
```

**Arguments:**
- `name`: Name of the asset/image
- `metadata`: Input metadata JSON file (from sbom_data_collector.py)
- `output`: Output SPDX JSON SBOM file
- `--validate`: Validate SBOM document after generation

### 3. `license_data.py`

Contains license mapping data for converting Fedora license names to SPDX identifiers.

**Features:**
- Maps 200+ Fedora license names to SPDX identifiers
- Includes comprehensive SPDX license ID list
- Supports both standard and custom license references

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure DNF/YUM is available on your system (standard on RHEL/Fedora/AlmaLinux)

## Example Workflow

1. **Collect system metadata:**
```bash
python sbom_data_collector.py -o almalinux-metadata.json --with-checksums --verbose
```

2. **Generate SBOM document:**
```bash
python sbom_generator.py "AlmaLinux-9.3-Cloud" almalinux-metadata.json almalinux-sbom.json --validate
```

## Output Formats

- **Metadata JSON**: Structured package and system information
- **SPDX JSON**: Industry-standard SBOM format compatible with security tools

## Requirements

- Python 3.6+
- DNF package manager
- Root/sudo access for system package inspection
- Network access for repository metadata (when using checksums)

## License Mapping

The toolkit includes comprehensive license mapping from Fedora's allowed licenses to SPDX identifiers, ensuring compliance with industry standards and security scanning tools.
