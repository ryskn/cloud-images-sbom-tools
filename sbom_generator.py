import argparse
import json
import uuid
from datetime import datetime

from spdx_tools.spdx.model.document import Document, CreationInfo
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.file import File
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.package import ExternalPackageRef, ExternalPackageRefCategory
from spdx_tools.spdx.writer.json.json_writer import write_document_to_file

GENERATOR_VERSION = '1.0'

def gen_uuid16():
    return uuid.uuid4().hex[:16]

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
    pkg_spdx = Package(
        spdx_id=pkg_spdx_id,
        name=pkg['name'],
        version=pkg['version'] + '-' + pkg['release'],
        supplier=Actor(ActorType.ORGANIZATION, pkg.get('vendor','Unknown')),
        originator=Actor(ActorType.ORGANIZATION, pkg.get('vendor','Unknown')),
        download_location=SpdxNoAssertion(),
        license_concluded=SpdxNoAssertion(),
        license_declared=None,
        copyright_text=SpdxNoAssertion(),
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
        created=datetime.utcnow()
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
    # Add Packages, Files, Relationships
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

    sbom_doc = generate_sbom(args.name, args.metadata)
    write_document_to_file(sbom_doc, args.output, args.validate)
    print(f'SPDX SBOM written to {output_path}')