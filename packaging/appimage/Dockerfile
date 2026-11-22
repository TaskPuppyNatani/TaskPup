FROM ubuntu@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        build-essential \
        ca-certificates \
        curl \
        desktop-file-utils \
        file \
        patchelf \
        python3.12=3.12.3-1ubuntu0.17 \
        python3.12-dev=3.12.3-1ubuntu0.17 \
        python3.12-venv=3.12.3-1ubuntu0.17 \
        squashfs-tools \
        tar \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-build.txt /opt/taskpup-requirements-build.txt

RUN python3.12 -m venv /opt/taskpup-build \
    && /opt/taskpup-build/bin/python -m pip install --no-cache-dir \
        --upgrade pip==25.3 \
    && /opt/taskpup-build/bin/python -m pip install --no-cache-dir \
        --no-deps PySide6==6.12.0 \
    && /opt/taskpup-build/bin/python -m pip install --no-cache-dir \
        -r /opt/taskpup-requirements-build.txt

RUN mkdir -p /opt/appimagetool \
    && curl --fail --location --retry 3 \
        https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage \
        --output /opt/appimagetool-x86_64.AppImage \
    && printf '%s  %s\n' \
        ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0 \
        /opt/appimagetool-x86_64.AppImage | sha256sum --check --status \
    && chmod 0755 /opt/appimagetool-x86_64.AppImage \
    && curl --fail --location --retry 3 \
        https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64 \
        --output /opt/runtime-x86_64 \
    && printf '%s  %s\n' \
        2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d \
        /opt/runtime-x86_64 | sha256sum --check --status \
    && chmod 0755 /opt/runtime-x86_64

COPY build-in-container.sh /usr/local/bin/taskpup-appimage-build
RUN chmod 0755 /usr/local/bin/taskpup-appimage-build

WORKDIR /src
