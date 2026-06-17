#!/bin/sh
# build-in-dockerharmony.sh
# Self-contained: clones repo, fetches deps, compiles binary_sign_tool
# Run inside hqzing/dockerharmony container
set -e

ALPINE="http://dl-cdn.alpinelinux.org/alpine/v3.22/main/aarch64"
REPO="https://github.com/nknkol/developtools_hapsigner.git"
WORKDIR="/tmp/build"

# ── Step 1: Install Alpine deps + zsh ─────────────────────────────────
echo ">>> Installing ncurses-libs, libcap, zsh"
curl -fsSL ${ALPINE}/APKINDEX.tar.gz | tar -zx -C /tmp
install_apk() { V=$(grep -A1 "^P:$1$" /tmp/APKINDEX | sed -n "s/^V://p"); curl -L -o /tmp/$1.apk ${ALPINE}/$1-${V}.apk; tar -zxf /tmp/$1.apk -C /; }
install_apk ncurses-libs
install_apk libcap
install_apk zsh

# ── Step 2: Install Harmonybrew ──────────────────────────────────────
echo ">>> Installing Harmonybrew"
zsh -c "$(curl -fsSL https://harmonybrew.atomgit.com/install.sh)"
export PATH="/storage/Users/currentUser/.harmonybrew/bin:$PATH"

# ── Step 3: Install build tools ──────────────────────────────────────
echo ">>> Installing openssl + ohsdk + make"
brew install openssl ohsdk make

# ── Step 3: Setup toolchain ──────────────────────────────────────────
export OHOS_SDK="/storage/Users/currentUser/.harmonybrew/opt/ohsdk"
export PATH="${OHOS_SDK}/native/llvm/bin:$PATH"

# ── Step 5: Clone repo ───────────────────────────────────────────────
echo ">>> Cloning repo"
rm -rf ${WORKDIR}
git clone --depth 1 ${REPO} ${WORKDIR}
cd ${WORKDIR}

# ── Step 6: Fetch third_party deps ───────────────────────────────────
echo ">>> Fetching third_party dependencies"
mkdir -p third_party

curl -fsSL https://github.com/serge1/ELFIO/archive/refs/heads/master.tar.gz | tar -zxf -
mv ELFIO-* third_party/third_party_elfio

curl -fsSL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz | tar -Jxf -
mv json third_party/third_party_json

git clone --depth 1 https://gitee.com/openharmony/third_party_bounds_checking_function.git \
  third_party/third_party_bounds_checking_function

curl -fsSL https://github.com/madler/zlib/archive/refs/heads/master.tar.gz | tar -zxf -
mv zlib-* third_party/third_party_zlib

# ── Step 7: Compile ──────────────────────────────────────────────────
echo ">>> Compiling binary_sign_tool"
make \
  CXX="clang++" \
  CXXFLAGS="-std=c++17 -fno-rtti -target aarch64-linux-ohos" \
  OPENSSL_PREFIX="/storage/Users/currentUser/.harmonybrew/opt/openssl" \
  PROJ="${WORKDIR}" \
  -j$(nproc)

echo ">>> Done"
ls -lh build/binary-sign-tool
file build/binary-sign-tool
