#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
command -v mvn >/dev/null 2>&1 || { echo "Optional FUSE build requires Maven (mvn)." >&2; exit 2; }

# Keep the FUSE module reproducible and isolated: install the freshly built core
# JAR into a project-local Maven repository, then resolve a normal Maven dependency.
./build.sh
MAVEN_REPO="$ROOT/build/maven-repository"
CORE_JAR="$ROOT/build/personalcloud.jar"
INSTALL_PLUGIN="org.apache.maven.plugins:maven-install-plugin:3.1.3:install-file"

mvn --no-transfer-progress -Dmaven.repo.local="$MAVEN_REPO" \
  "$INSTALL_PLUGIN" \
  -Dfile="$CORE_JAR" \
  -DgroupId=dev.personalcloud \
  -DartifactId=personalcloud-core \
  -Dversion=0.2.0 \
  -Dpackaging=jar \
  -DgeneratePom=true

mvn --no-transfer-progress -Dmaven.repo.local="$MAVEN_REPO" \
  -f integrations/linux/fuse/pom.xml clean package

JAR="$ROOT/integrations/linux/fuse/target/personalcloud-linux-fuse-0.2.0.jar"
test -s "$JAR"
jar tf "$JAR" | grep -Fxq 'dev/personalcloud/linux/fuse/FuseMountMain.class'
jar tf "$JAR" | grep -Fxq 'dev/personalcloud/control/LocalControlClient.class'
jar tf "$JAR" | grep -Fxq 'ru/serce/jnrfuse/FuseStubFS.class'
java -jar "$JAR" --help >/dev/null
printf '\nBuilt and launch-smoke-tested: %s\n' "$JAR"
