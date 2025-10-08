import argparse
import logging
import json
import xml.etree.ElementTree as ET

import dnf


def get_distribution():
    dist_info = {}
    with open('/etc/os-release') as f:
        for line in f:
            if '=' in line:
                key, val = line.strip().split('=', 1)
                dist_info[key] = val.strip('"')
    return {
        'name': dist_info.get('NAME'),
        'version': dist_info.get('VERSION_ID')
    }

def collect_system_metadata(checksums: bool = False):
    metadata = {
        'distribution': get_distribution(),
        'packages': {}
    }

    base = dnf.Base()
    base.fill_sack()

    logging.debug('Retrieving installed packages')
    installed_pkgs = list(base.sack.query().installed())
    for dnf_pkg in installed_pkgs:
        logging.debug(f'Adding data for {dnf_pkg.name}')
        evr = f"{dnf_pkg.e or '0'}:{dnf_pkg.v}-{dnf_pkg.r}"
        metadata['packages'][dnf_pkg.name] = {
            'name': dnf_pkg.name,
            'epoch': dnf_pkg.e or '0',
            'version': dnf_pkg.v,
            'release': dnf_pkg.r,
            'arch': dnf_pkg.a,
            'evr': evr,
            'repo': dnf_pkg.repoid,
            'checksum': None,
            'sourcerpm': dnf_pkg.sourcerpm,
            'license': None if dnf_pkg.license == '<NULL>' else dnf_pkg.license,
            'vendor': dnf_pkg.vendor,
            'files': dnf_pkg.files,
        }

    # we want the checksum to retrieve AlmaLinux SBOM data
    if checksums:
        # package quick lookup: (name, evr)
        installed_map = {(pkg.name, f'{pkg.e}:{pkg.v}-{pkg.r}'): pkg for pkg in installed_pkgs}
        logging.debug('Reading repositories to collect checksums')
        base.read_all_repos()
        base.fill_sack()
        for repo in base.repos.iter_enabled():
            primary_xml = repo.get_metadata_content('primary')
            if not primary_xml:
                continue
            root = ET.fromstring(primary_xml)
            ns = {'rpm': root.tag[root.tag.find('{')+1 : root.tag.find('}')]}
            for pkg_el in root.findall('rpm:package', ns):
                name = pkg_el.findtext('rpm:name', namespaces=ns)
                version_el = pkg_el.find('rpm:version', ns)
                if version_el is None:
                    continue
                evr = (
                    f"{version_el.attrib.get('epoch','0')}"
                    f":{version_el.attrib.get('ver','')}"
                    f"-{version_el.attrib.get('rel','')}"
                )
                key = (name, evr)
                dnf_pkg = installed_map.get(key)
                if not dnf_pkg:
                    continue
                checksum_el = pkg_el.find('rpm:checksum', ns)
                metadata['packages'][name]['checksum'] = {
                    'type': checksum_el.attrib.get('type') if checksum_el is not None else None,
                    'value': checksum_el.text if checksum_el is not None else None,
                }
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='AlmaLinux Cloud Images SBOM data collector'
    )

    parser.add_argument(
        '-wc', '--with-checksums',
        action='store_true',
        help='collect available checksums from repository data'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='enable verbose output'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='output file'
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    logging.info('Collecting SBOM data from the system')
    metadata = collect_system_metadata(args.with_checksums)
    with open(args.output, 'w') as output_file:
        json.dump(metadata, output_file)
    logging.info('SBOM data wrote to: %s', args.output)