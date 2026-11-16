#!/bin/sh
test -n "$1" && { echo This script has no options. It updates the referenced Frida version in makefile to the most current one. ; exit 1 ; }

OLD=$(grep -E '^FRIDA_VERSION[[:space:]]*=' Makefile 2>/dev/null | awk -F= '{print $2}' | tr -d '[:space:]')
# GitHub redirects /releases/latest to /releases/tag/<version>
NEW=$(curl -s -o /dev/null -w '%{redirect_url}' https://github.com/frida/frida/releases/latest | sed 's|.*/tag/||' | tr -d '[:space:]')
echo "$NEW" | grep -Eq '^[0-9]+(\.[0-9]+)+$' || { echo "Could not determine newest Frida version (got: '$NEW')" ; exit 1 ; }

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
