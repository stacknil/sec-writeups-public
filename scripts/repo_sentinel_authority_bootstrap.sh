#!/bin/sh

# The workflow launch envelope must supply both paths from reviewed configuration.
set -eu
umask 077

if [ "$#" -lt 2 ]; then
    exit 2
fi

trusted_python=$1
controller=$2
shift 2

case "$trusted_python" in
    /*) ;;
    *) exit 2 ;;
esac
case "$controller" in
    /*) ;;
    *) exit 2 ;;
esac

if [ ! -x "$trusted_python" ] || [ ! -f "$controller" ]; then
    exit 2
fi

# These variables must not reach the dynamic loader for env or Python. They may
# already have affected this shell, which is why the parent launch is trusted.
unset LD_PRELOAD LD_LIBRARY_PATH
unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
unset DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH
unset BASH_ENV ENV CDPATH GLOBIGNORE

exec /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    "$trusted_python" -I -S -B "$controller" "$@"
