#!/usr/bin/env python3
# Streamlining hackendeck setups

import sys
import os
import subprocess
import logging

KSSHASKPASS = '/usr/bin/ksshaskpass'
SSHD_CONFIG = '/etc/ssh/sshd_config'

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    hackendeck = ( subprocess.run('grep -e "^ID=manjaro$" /etc/os-release', shell=True).returncode == 0 )
    if not hackendeck:
        # plz send patches towards support for other distros ..
        logger.info('Only supported on Manjaro - please check documentation')
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
    install_packages = ( subprocess.run('pacman -Qi avahi dbus-python zenity >/dev/null', shell=True).returncode != 0 )
    if install_packages:
        logger.info('installing packages for the service')
        subprocess.check_call('sudo -A pacman -S avahi dbus-python zenity', shell=True)

    enable_avahi = ( subprocess.run('systemctl status avahi-daemon 2>&1 >/dev/null', shell=True).returncode != 0 )
    if enable_avahi:
        logger.info('avahi-daemon needs to be enabled')
        subprocess.check_call('sudo -A systemctl enable --now avahi-daemon', shell=True)
    logger.info('avahi-daemon is enabled')

    logger.info('======== hackendeck configuration complete ==========')
