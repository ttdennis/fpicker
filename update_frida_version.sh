#!/bin/sh
test -n "$1" && { echo This script has no options. It updates the referenced Frida version in makefile to the most current one. ; exit 1 ; }

OLD=$(grep -E '^FRIDA_VERSION\s*=' Makefile 2>/dev/null | awk -F= '{print $2}' | tr -d '[:space:]')
NEW=$(curl https://github.com/frida/frida/releases/ 2>/dev/null|grep 'Frida\ [0-9.]*'|head -n 1|sed 's/.*Frida\ //'| sed 's/<\/h2>//')

echo Current set version: $OLD
echo Newest available version: $NEW

test -z "$OLD" -o -z "$NEW" -o "$OLD" = "$NEW" && { echo Nothing to be done. ; exit 0 ; }

# Determine the correct sed command
case $(sed --help 2>&1) in
  *GNU*) set sed -i;;
  *) set sed -i '';;
esac

"$@" "s/=\ $OLD/=\ $NEW/" Makefile || exit 1
echo Successfully updated Makefile
