#!/bin/sh
# Run the test suite under Jython against Burp's real Extender API interfaces.
#   JYTHON_JAR  Jython standalone jar  (default: /opt/BurpSuitePro/jython-standalone-2.7.2.jar)
#   BURP_JAR    Burp Suite jar         (default: /opt/BurpSuitePro/burpsuite.jar)
set -eu

JYTHON_JAR="${JYTHON_JAR:-/opt/BurpSuitePro/jython-standalone-2.7.2.jar}"
BURP_JAR="${BURP_JAR:-/opt/BurpSuitePro/burpsuite.jar}"
HERE="$(cd "$(dirname "$0")" && pwd)"
API_DIR="$(mktemp -d)"  # left for the OS temp cleaner: exec replaces this shell

# Only the burp/I*.class interfaces are needed; avoid loading the whole Burp jar.
(cd "$API_DIR" && unzip -q "$BURP_JAR" 'burp/I*.class')

exec java -Djava.awt.headless=true --enable-native-access=ALL-UNNAMED \
     -Dpython.path="$API_DIR:$HERE/.." \
     -jar "$JYTHON_JAR" "$HERE/test_jwt_auth_matrix.py"
