# Shieldly CLI — AI-Powered Security Analysis for AWS
# The published CLI is a single self-contained CJS bundle (dist/cli.cjs),
# so the image is just Node 24 + that file. No npm install at build time.
#
#   docker run --rm -v "$PWD":/work ghcr.io/shieldly-io/cli analyze-iam /work/policy.json
FROM node:24-alpine

LABEL org.opencontainers.image.title="Shieldly CLI" \
      org.opencontainers.image.description="AI-Powered Security Analysis for AWS — official CLI" \
      org.opencontainers.image.source="https://github.com/shieldly-io/cli" \
      org.opencontainers.image.url="https://www.shieldly.io" \
      org.opencontainers.image.licenses="MIT"

COPY dist/cli.cjs /usr/local/lib/shieldly/cli.cjs
RUN printf '#!/bin/sh\nexec node /usr/local/lib/shieldly/cli.cjs "$@"\n' > /usr/local/bin/shieldly \
  && chmod +x /usr/local/bin/shieldly

WORKDIR /work
ENTRYPOINT ["shieldly"]
CMD ["--help"]
