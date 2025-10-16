import argparse
import logging
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

try:
    import dnf
except ImportError:
    dnf = None


def get_distribution(installroot: Optional[str] = None):
    dist_info = {}
    os_release = "/etc/os-release"
    if installroot:
        os_release = os.path.join(installroot, "etc/os-release")

    try:
        with open(os_release) as f:
            for line in f:
                if '=' in line:
                    key, val = line.strip().split('=', 1)
                    dist_info[key] = val.strip('"')
    except FileNotFoundError:
        pass

    return {
        'name': dist_info.get('NAME', 'Unknown'),
        'version': dist_info.get('VERSION_ID', 'Unknown')
    }


def _detect_rpmdb_path(installroot: str) -> str:
    """Detect the RPM database path under the given root."""
    for relpath in ["usr/lib/sysimage/rpm", "var/lib/rpm"]:
        abspath = os.path.join(installroot, relpath)
        if os.path.isdir(abspath) and (
            os.path.isfile(os.path.join(abspath, "rpmdb.sqlite")) or
            os.path.isfile(os.path.join(abspath, "Packages"))
        ):
            return abspath
    raise FileNotFoundError(f"rpmdb not found under {installroot}")


def _collect_with_rpm_cli(installroot: Optional[str], dbpath: str) -> dict:
    """Collect package metadata using rpm CLI."""
    metadata = {
        'distribution': get_distribution(installroot),
        'packages': {}
    }

    qf = "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SOURCERPM}|%{LICENSE}|%{VENDOR}\\n"
    cmd = ["rpm", "--dbpath", dbpath, "-qa", "--qf", qf]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
    except subprocess.TimeoutExpired:
        logging.error("rpm command timed out after 60 seconds")
        raise RuntimeError("rpm command timed out")
    except subprocess.CalledProcessError as e:
        logging.error(f"rpm command failed with exit code {e.returncode}")
        if e.stderr:
            logging.error(f"rpm stderr: {e.stderr}")
        raise RuntimeError(f"rpm command failed: {e}")
    except FileNotFoundError:
        logging.error("rpm command not found. Please install rpm.")
        raise RuntimeError("rpm command not found")

    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 8:
            continue

        name, epoch, ver, rel, arch, src, lic, vendor = parts[:8]
        epoch = "0" if epoch == "(none)" else epoch
        src = None if src == "(none)" else src

        evr = f"{epoch}:{ver}-{rel}"
        metadata['packages'][name] = {
            'name': name,
            'epoch': epoch,
            'version': ver,
            'release': rel,
            'arch': arch,
            'evr': evr,
            'repo': '@System',
            'checksum': None,
            'sourcerpm': src,
            'license': lic if lic != "(none)" else None,
            'vendor': vendor if vendor != "(none)" else None,
            'files': [],
        }

    if not metadata['packages']:
        logging.warning("rpm CLI returned 0 packages")

    return metadata


def collect_system_metadata(checksums: bool = False, installroot: Optional[str] = None):
    # Convert to absolute, canonical path (resolves symlinks for security)
    if installroot:
        installroot = os.path.realpath(installroot)
        if not os.path.isdir(installroot):
            raise ValueError(f"installroot does not exist or is not a directory: {installroot}")

    # Try dnf first
    if dnf:
        try:
            base = dnf.Base()
            if installroot:
                dbpath = _detect_rpmdb_path(installroot)
                base.conf.installroot = installroot
                base.conf.dbpath = os.path.relpath(dbpath, installroot)
            base.fill_sack()

            logging.debug('Retrieving installed packages via dnf')
            installed_pkgs = list(base.sack.query().installed())

            # Always fall back if 0 packages (consistent behavior)
            if not installed_pkgs:
                logging.warning('dnf found 0 packages, falling back to rpm CLI')
                raise RuntimeError("dnf returned empty")

            metadata = {
                'distribution': get_distribution(installroot),
                'packages': {}
            }

            for dnf_pkg in installed_pkgs:
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
                    'vendor': None if dnf_pkg.vendor == '<NULL>' else dnf_pkg.vendor,
                    'files': dnf_pkg.files,
                }

            if checksums:
                _augment_checksums(base, metadata, installed_pkgs)

            return metadata

        except Exception as e:
            logging.warning(f'dnf failed: {e}, falling back to rpm CLI')

    # Fallback to rpm CLI
    logging.info('Using rpm CLI fallback')
    
    if checksums:
        logging.warning('Checksums are not supported with rpm CLI fallback')

    if installroot:
        dbpath = _detect_rpmdb_path(installroot)
    else:
        dbpath = _detect_rpmdb_path("/")

    return _collect_with_rpm_cli(installroot, dbpath)


def _augment_checksums(base, metadata: dict, installed_pkgs: list):
    """Add checksums from repository metadata."""
    installed_map = {(pkg.name, f'{pkg.e or "0"}:{pkg.v}-{pkg.r}'): True for pkg in installed_pkgs}

    base.read_all_repos()
    for repo in base.repos.iter_enabled():
        try:
            primary_xml = repo.get_metadata_content('primary')
        except Exception:
            continue

        if not primary_xml:
            continue

        try:
            root = ET.fromstring(primary_xml)
        except ET.ParseError:
            continue

        ns = {'rpm': root.tag[root.tag.find('{')+1:root.tag.find('}')]}

        for pkg_el in root.findall('rpm:package', ns):
            name = pkg_el.findtext('rpm:name', namespaces=ns)
            version_el = pkg_el.find('rpm:version', ns)
            if version_el is None or not name:
                continue

            evr = (
                f"{version_el.attrib.get('epoch', '0')}"
                f":{version_el.attrib.get('ver', '')}"
                f"-{version_el.attrib.get('rel', '')}"
            )

            if (name, evr) not in installed_map:
                continue

            checksum_el = pkg_el.find('rpm:checksum', ns)
            if name in metadata['packages']:
                metadata['packages'][name]['checksum'] = {
                    'type': checksum_el.attrib.get('type') if checksum_el is not None else None,
                    'value': checksum_el.text if checksum_el is not None else None,
                }


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
    parser.add_argument(
        '--root',
        type=str,
        help='use target directory as the root (rpmdb will be discovered under it)'
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    logging.info('Collecting SBOM data from the system%s',
                 f' (root={args.root})' if args.root else '')

    metadata = collect_system_metadata(
        checksums=args.with_checksums,
        installroot=args.root
    )

    with open(args.output, 'w') as output_file:
        json.dump(metadata, output_file)

    logging.info('SBOM data written to: %s', args.output)
