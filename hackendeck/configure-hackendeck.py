#!/usr/bin/env python3
# Streamlining hackendeck setups

import sys
import os
import subprocess
import logging

KSSHASKPASS = '/usr/bin/ksshaskpass'
SSHD_CONFIG = '/etc/ssh/sshd_config'

def check_distro_supported():
    try:
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
            if 'ID=manjaro' in os_release:
                return True
            for line in os_release.split('\n'):
                if line.startswith('ID_LIKE'):
                    if 'fedora' in line:
                        return True
    except FileNotFoundError:
        return False
    return False

def install_packages():
    # Check the package manager and install the necessary packages
    try:
        if subprocess.run('command -v pacman', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            # Using pacman
            packages = 'avahi dbus-python zenity'
            subprocess.check_call(f'sudo -A pacman -S --noconfirm {packages}', shell=True)
        elif subprocess.run('command -v dnf', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
            # Using dnf
            packages = 'avahi dbus-python zenity'
            subprocess.check_call(f'sudo dnf install -y {packages}', shell=True)
        else:
            logger.error('No supported package manager found.')
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        logger.error(f'Failed to install packages: {e}')
        sys.exit(1)

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    if not check_distro_supported():
        # plz send patches towards support for other distros ..
        logger.info('Only supported on Manjaro and Fedora-based distros - please check documentation')
        sys.exit(1)

    logger.info('======== Running hackendeck configuration checks ==========')

    # some gross hack to escape the scout LD_* setup (causes pacman etc. tools to fail)
    os.environ['LD_LIBRARY_PATH'] = ''

    assert os.path.exists(KSSHASKPASS)
    os.environ['SUDO_ASKPASS'] = KSSHASKPASS

    enable_sshd = ( subprocess.run('systemctl status sshd 2>&1 >/dev/null', shell=True).returncode != 0 )
    if enable_sshd:
        logger.info('sshd needs to be enabled')
        subprocess.check_call('sudo -A systemctl enable --now sshd', shell=True)
    logger.info('sshd is enabled')

    # pretty sure those are installed by default, but just in case ..
    install_packages()

    enable_avahi = ( subprocess.run('systemctl status avahi-daemon 2>&1 >/dev/null', shell=True).returncode != 0 )
    if enable_avahi:
        logger.info('avahi-daemon needs to be enabled')
        subprocess.check_call('sudo -A systemctl enable --now avahi-daemon', shell=True)
    logger.info('avahi-daemon is enabled')

    logger.info('======== hackendeck configuration complete ==========')
