project('steamos-devkit-service', 'c')
dependencies = [
    dependency('glib-2.0'),
    dependency('gio-unix-2.0'),
    dependency('json-glib-1.0'),
    dependency('libsoup-2.4'),
    dependency('avahi-client'),
    dependency('avahi-glib'),
    dependency('libsystemd'),
]
executable('steamos-devkit-service', ['main.c', 'avahi-service.c', 'utils.c', 'json.c'], dependencies : dependencies)
