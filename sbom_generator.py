import argparse
import json
import logging
import uuid
import re
import sys

from datetime import datetime, timezone

from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model.document import Document, CreationInfo
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.file import File
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.package import ExternalPackageRef, ExternalPackageRefCategory
from spdx_tools.spdx.model.extracted_licensing_info import ExtractedLicensingInfo
from spdx_tools.spdx.writer.json.json_writer import write_document_to_file


from license_data import FEDORA_SPDX_ID_MAP, SPDX_IDS

GENERATOR_VERSION = '1.0'
SUPPLIER_ORG = 'AlmaLinux OS Foundation'

def gen_uuid16():
    return uuid.uuid4().hex[:16]

def process_license_expression(license_text):
    """
    Process a license string and return both the raw license and SPDX-compliant version.
    Returns spdx_license_parsed
    """
    if not license_text or license_text.strip() == '':
        return SpdxNoAssertion()

    spdx_license_text = convert_to_spdx_format(license_text)
    spdx_license_parsed = spdx_licensing.parse(spdx_license_text)

    return spdx_license_parsed

def convert_to_spdx_format(license_text):
    """
    Convert license text to SPDX-compliant format:
    - Single valid SPDX license: use as-is
    - Single non-valid SPDX license: create LicenseRef-
    - Multi-part expressions: create single LicenseRef- for entire expression
    """
    if not license_text or license_text.strip() == '':
        return SpdxNoAssertion()

    license_text = license_text.strip()

    # First, check if this is already a valid single SPDX license or can be mapped
    if license_text in SPDX_IDS or license_text in FEDORA_SPDX_ID_MAP:
        return convert_single_license(license_text)

    normalized_text = license_text

    # Only normalize standalone "and" and "or" words, not those within license IDs
    # Use word boundaries and negative lookbehind/lookahead to avoid matching within license IDs
    normalized_text = re.sub(
        r'(?<![a-zA-Z0-9.-])\b(and)\b(?![a-zA-Z0-9.-])', 'AND', normalized_text, flags=re.IGNORECASE
    )
    normalized_text = re.sub(
        r'(?<![a-zA-Z0-9.-])\b(or)\b(?![a-zA-Z0-9.-])', 'OR', normalized_text, flags=re.IGNORECASE
    )

    # Check if this is a multi-part expression
    if re.search(r'\b(AND|OR)\b', normalized_text):
        # Multi-part expression: create single LicenseRef- for entire expression
        return create_license_ref_from_expression(normalized_text)
    else:
        # Single license: process normally
        return convert_single_license(license_text)

def create_license_ref_from_expression(license_expression):
    """
    Create a single LicenseRef- for a multi-part license expression.
    """
    # Split by operators while preserving them
    parts = re.split(r'\s+(AND|OR)\s+', license_expression)

    # Process individual license parts
    # Convert to SPDX if valid, keep original otherwise
    processed_parts = []
    for part in parts:
        if part.strip() in ['AND', 'OR']:
            processed_parts.append(part.strip())
        else:
            license_part = part.strip()
            if license_part in SPDX_IDS:
                processed_parts.append(license_part)
            elif license_part in FEDORA_SPDX_ID_MAP:
                processed_parts.append(FEDORA_SPDX_ID_MAP[license_part])
            else:
                # Keep original license text for non-valid licenses
                processed_parts.append(license_part)

    expression_string = '-'.join(processed_parts)
    sanitized_expression = sanitize_license_ref_name(expression_string)

    return f'LicenseRef-{sanitized_expression}'

def sanitize_license_ref_name(name):
    """
    Sanitize a string to be used in a LicenseRef- identifier.
    """
    return (
        name.replace(' ', '-')
            .replace('/', '-')
            .replace('+', '-')
            .replace('(', '')
            .replace(')', '')
            .replace(',', '')
    )

def convert_single_license(license_text):
    """
    Convert a single Fedora license name to SPDX license identifier.
    """
    if not license_text or license_text.strip() == '':
        return SpdxNoAssertion()
    license_text = license_text.strip()
    # Check if already a valid SPDX ID
    if license_text in SPDX_IDS:
        return license_text
    # Try to map from Fedora naming to SPDX
    if license_text in FEDORA_SPDX_ID_MAP:
        return FEDORA_SPDX_ID_MAP[license_text]
    # If no mapping found, create a LicenseRef
    sanitized_name = sanitize_license_ref_name(license_text)
    return f'LicenseRef-{sanitized_name}'

def gen_pkg_spdx_id(pkg_name):
    chars_to_replace = ['_', '+']
    for char in chars_to_replace:
        pkg_name = pkg_name.replace(char, '-')
    return f'SPDXRef-Package-rpm-{pkg_name}-{gen_uuid16()}'

def sanitize_cpe_pkg_name(name):
    if not name:
        return "-"
    result = []
    for ch in name:
        if ch.isalnum() or ch in "._-":
            result.append(ch)
        else:
            result.append(f"\\{ch}")
    return "".join(result)

def build_package_component(pkg, distro):
    pkg_spdx_id = gen_pkg_spdx_id(pkg['name'])
    # Process license information
    pkg_license = pkg.get('license')
    spdx_license_parsed = (
        'NOASSERTION' if not pkg_license
        else process_license_expression(pkg_license)
    )
    pkg_vendor = pkg.get('vendor')
    vendor = (
        SpdxNoAssertion() if not pkg_vendor
        else Actor(ActorType.ORGANIZATION, pkg_vendor)
    )
    pkg_spdx = Package(
        spdx_id=pkg_spdx_id,
        name=pkg['name'],
        version=pkg['version'] + '-' + pkg['release'],
        supplier=Actor(ActorType.ORGANIZATION, SUPPLIER_ORG),
        originator=vendor,
        download_location=SpdxNoAssertion(),
        license_concluded=spdx_license_parsed,
        license_declared=spdx_license_parsed,
        copyright_text=SpdxNoAssertion(),
        source_info='acquired info from RPM database',
        summary=None,
        description=None,
    )
    pkg_spdx.external_references = [
        ExternalPackageRef(
            category=ExternalPackageRefCategory.SECURITY,
            reference_type='cpe23Type',
            locator=(
                f"cpe:2.3:a:almalinux:{sanitize_cpe_pkg_name(pkg['name'])}"
                f":{pkg['epoch']}\\:{pkg['version']}-{pkg['release']}"
                ":*:*:*:*:*:*:*"
            )
        ),
        ExternalPackageRef(
            category=ExternalPackageRefCategory.PACKAGE_MANAGER,
            reference_type='purl',
            locator=(
                f"pkg:rpm/almalinux/{pkg['name']}@{pkg['version']}-{pkg['release']}"
                f"?arch={pkg['arch']}&epoch={pkg['epoch']}&distro={distro.lower()}"
                f"&upstream={pkg['sourcerpm']}"
            )
        )
    ]
    return pkg_spdx

def build_file_component(path):
    file_id = f'SPDXRef-{gen_uuid16()}'
    f = File(
        spdx_id=file_id,
        name=path.lstrip('/'),
        checksums=[
            Checksum(ChecksumAlgorithm.SHA1, '0000000000000000000000000000000000000000')
        ],
        license_concluded=SpdxNoAssertion(),
        copyright_text=""
    )
    return f

def generate_sbom(name, metadata_path):
    with open(metadata_path, 'r') as metadata_file:
        metadata = json.load(metadata_file)

    # Build SPDX Document
    creation_info = CreationInfo(
        spdx_version='SPDX-2.3',
        spdx_id='SPDXRef-DOCUMENT',
        name=f'{name}',
        document_namespace=f'https://security.almalinux.org/spdx-{name}-{uuid.uuid4()}',
        creators=[
            Actor(
                ActorType.TOOL,
                f'AlmaLinux OS Cloud Images SBOM Generator {GENERATOR_VERSION}'
            )
        ],
        created=datetime.now(timezone.utc)
    )

    doc = Document(
        creation_info=creation_info,
    )

    doc.relationships.append(
        Relationship(
            spdx_element_id='SPDXRef-DOCUMENT',
            relationship_type=RelationshipType.DESCRIBES,
            related_spdx_element_id='SPDXRef-DOCUMENT'
        )
    )

    distro = metadata["distribution"]
    distro_for_purl = f"{distro['name']}-{distro['version'].split('.')[0]}"
    extracted_licensing_info = {}

    # Add Packages, Files, Relationships, LicenseRefs
    for pkg in metadata["packages"].values():
        pkg_obj = build_package_component(pkg, distro_for_purl)
        doc.packages.append(pkg_obj)

        for fpath in pkg.get('files', []):
            file_obj = build_file_component(fpath)
            doc.files.append(file_obj)
            rel = Relationship(
                spdx_element_id=pkg_obj.spdx_id,
                relationship_type=RelationshipType.CONTAINS,
                related_spdx_element_id=file_obj.spdx_id
            )
            doc.relationships.append(rel)

        pkg_license = str(pkg_obj.license_concluded)
        if not pkg_license:
            continue
        if pkg_license not in SPDX_IDS:
            if pkg_license not in extracted_licensing_info:
                extracted_licensing_info[pkg_license] = pkg.get('license').removeprefix("LicenseRef-")

    for license_id, license_name in extracted_licensing_info.items():
        eli = ExtractedLicensingInfo(
            license_id=license_id,
            license_name=license_name,
            extracted_text='NONE',
        )
        doc.extracted_licensing_info.append(eli)

    return doc

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate SPDX SBOM from metadata')
    parser.add_argument('name', help='name of the asset')
    parser.add_argument('metadata', help='input metadata JSON file')
    parser.add_argument('output', help='output SPDX JSON SBOM file')
    parser.add_argument(
        '--validate', help='validate SBOM document at the end', action='store_true'
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    try:
        sbom_doc = generate_sbom(args.name, args.metadata)
    except Exception as e:
        logging.error(f"Error generating SBOM: {e}", exc_info=True)
        sys.exit(1)
    write_document_to_file(sbom_doc, args.output, args.validate)
    logging.info(f'SPDX SBOM written to {args.output}')
