#!/usr/bin/env python


def install(alsi):
    alsi.pip_install('cchardet')


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
