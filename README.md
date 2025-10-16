# AlmaLinux cloud images SBOM tools

Utility tools to help in the process of generating SBOM (Software Bill of Materials) documents for AlmaLinux cloud images and other Linux distributions based on Fedora.

## Overview

This toolkit provides a complete solution for collecting system metadata and generating SPDX-compliant SBOM documents from AlmaLinux and Fedora-based systems. The generated SBOMs include detailed package information, license data, and file relationships.

## Features

- **System metadata collection** from installed RPM packages
- **SPDX 2.3 compliant** SBOM generation with complete document structure
- **Advanced license processing** with sophisticated conversion from Fedora license expressions to SPDX identifiers
- **Comprehensive license mapping** covering 200+ Fedora license names to SPDX format
- **Package checksum collection** from repository metadata (optional)
- **CPE and PURL** external references for security and package management integration
- **File-level tracking** and relationships within packages
- **SBOM validation** support for ensuring document compliance
- **Comprehensive logging** and debugging support

## Scripts

### 1. `sbom_data_collector.py`

Collects comprehensive metadata from the system's installed packages.

**Features:**
- Extracts package information (name, version, release, architecture, etc.)
- Collects license, vendor, and source RPM information
- Optionally retrieves package checksums from repository metadata
- **Fallback mechanism**: Works without DNF/RPM Python bindings by using `rpm` CLI
- Outputs structured JSON metadata

**Usage:**
```bash
# Scan the current system
python sbom_data_collector.py -o metadata.json

# Scan an extracted/mounted root filesystem
python sbom_data_collector.py --root /path/to/rootfs -o metadata.json
```

**Options:**
- `-o, --output`: Output JSON file (required)
- `--root`: Use target directory as the root filesystem (extracted or mounted)
- `-wc, --with-checksums`: Collect available checksums from repository data
- `-v, --verbose`: Enable verbose output

**Limitations:**
- `--with-checksums` is only supported when using DNF bindings. When falling back to rpm CLI, checksums will not be collected.

### 2. `sbom_generator.py`

Generates SPDX 2.3 compliant SBOM documents from collected metadata with advanced license processing.

**Features:**
- Creates SPDX JSON format SBOM documents with complete document structure
- Processes complex license expressions and converts them to SPDX-compliant format
- Handles single licenses, multi-part expressions (AND/OR), and custom license references
- Generates unique SPDX IDs for packages and files with proper naming conventions
- Includes external references (CPE 2.3 and PURL) for security and package management tools
- Establishes comprehensive package-file relationships
- Supports extracted licensing information for non-standard licenses
- Optional SBOM validation using spdx-tools library

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

Contains comprehensive license mapping data for converting Fedora license names to SPDX identifiers.

**Features:**
- Maps 200+ Fedora license names to SPDX identifiers with precise matching
- Includes complete SPDX license ID list (900+ identifiers) for validation
- Supports standard SPDX licenses, deprecated licenses, and LicenseRef- custom references
- Handles complex license expressions with proper SPDX formatting
- Provides fallback mechanisms for unmapped licenses

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. For scanning external filesystems, extract or mount the target rootfs to a directory

## Dependencies

- **spdx-tools** (0.8.3): SPDX library for creating and validating SPDX documents
- **dnf/rpm** (optional): For native Python bindings. Falls back to `rpm` CLI if unavailable

## Example Workflow

### Scan the current system
```bash
python sbom_data_collector.py -o almalinux-metadata.json --with-checksums --verbose
python sbom_generator.py "AlmaLinux-9.3-Cloud" almalinux-metadata.json almalinux-sbom.json --validate
```

### Scan an extracted container filesystem
```bash
python sbom_data_collector.py --root /path/to/rootfs -o container-metadata.json
python sbom_generator.py "AlmaLinux 10 Container" container-metadata.json container-sbom.json
```

## Output Formats

- **Metadata JSON**: Structured package and system information including:
  - Distribution details (name, version)
  - Package metadata (name, version, license, vendor, files)
  - Optional checksums from repository data
- **SPDX JSON**: SPDX 2.3 compliant SBOM format including:
  - Document creation info and namespace
  - Package definitions with license conclusions
  - File listings and relationships
  - External references (CPE 2.3 and PURL identifiers)
  - Extracted licensing information for custom licenses
  - Full compatibility with security scanning and compliance tools

## Requirements

- Python 3.8+
- **spdx-tools** (0.8.3): Required for SPDX document creation and validation
- **rpm** CLI tool: Required for fallback collection when Python bindings unavailable
- Root/sudo access may be required for system package inspection

## License Mapping

The toolkit includes sophisticated license processing capabilities:

- **Comprehensive mapping**: Converts 200+ Fedora license names to SPDX identifiers
- **Complex expression handling**: Processes multi-part license expressions (AND/OR operators)
- **SPDX compliance**: Ensures all licenses conform to SPDX 2.3 specification
- **Custom license support**: Creates LicenseRef- identifiers for unmapped licenses
- **Validation**: Uses complete SPDX license list (900+ identifiers) for verification
- **Industry compatibility**: Ensures compatibility with security scanning and compliance tools
