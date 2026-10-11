# jimmy benchmark lab: a deliberately restricted shell with
# application-level policy weaknesses + false leads (see repo README).
# Build from the REPO ROOT (needs jimmy/lab/rshell.py):
#   docker build -t jimmy-lab:latest -f targets/restricted-lab/Dockerfile .
FROM debian:bookworm-slim

RUN apt-get update && apt-get -y --no-install-recommends install \
        python3 procps && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /usr/local/bin/rshell lab

# The restricted shell and its companion "textedit"/"more" applications are
# the same payloads as the local demo target, so benchmark results transfer.
COPY jimmy/lab/rshell.py /usr/local/lib/jimmy-rshell.py
RUN printf '#!/bin/sh\nexec python3 -u /usr/local/lib/jimmy-rshell.py "$@"\n' \
          > /usr/local/bin/rshell && \
    chmod 755 /usr/local/bin/rshell && \
    printf '# textedit system profile\nallow_shell=0\n' > /etc/texteditrc

USER lab
WORKDIR /home/lab
# Sentinel arming happens from the control plane (DockerTarget.reset) so the
# container stays idempotent across re-runs.
CMD ["sleep", "infinity"]
