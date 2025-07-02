#!/bin/sh
set -e

# 1: Sigma Merge default in, but don’t overwrite any custom rules
cp -Rn /opt/sigma/default/rules/* /opt/sigma/custom/rules/

# 2: Expose a unified view at /sigma
mkdir -p /sigma
# cp -a /opt/sigma/custom/rules /sigma
cp -r --no-preserve=mode,ownership /opt/sigma/custom/rules /sigma
# cp -an /opt/sigma/default/rules/* /sigma/
cp -rn --no-preserve=mode,ownership /opt/sigma/default/rules/* /sigma/

# 3: Chainsaw: merge default -> /chainsaw-rules
#    (host volume at /chainsaw-rules can override/add)
cp -Rn /opt/chainsaw/rules/* /chainsaw-rules/

exec "$@"