#!/bin/sh
# build-in-dockerharmony.sh
# Self-contained: clones repo, fetches deps, compiles binary_sign_tool
# Run inside hqzing/dockerharmony container
set -e

REPO="https://github.com/nknkol/developtools_hapsigner.git"
WORKDIR="/tmp/build"

# ── Step 1: Install zsh ──────────────────────────────────────────────
echo ">>> Installing zsh"
curl -fLO https://github.com/Harmonybrew/ohos-zsh/releases/download/5.9/zsh-5.9-ohos-arm64.tar.gz
tar -zxf zsh-5.9-ohos-arm64.tar.gz -C /opt
ln -s /opt/zsh-5.9-ohos-arm64/bin/zsh /usr/bin/zsh

# ── Step 2: Install Harmonybrew ──────────────────────────────────────
echo ">>> Installing Harmonybrew"
zsh -c "$(curl -fsSL https://harmonybrew.atomgit.com/install.sh)"
eval "$(/storage/Users/currentUser/.harmonybrew/bin/brew shellenv)"

# ── Step 3: Install build tools ──────────────────────────────────────
echo ">>> Installing build tools"
eval "$(/storage/Users/currentUser/.harmonybrew/bin/brew shellenv)"
brew install openssl ohos-sdk make git

# ── Step 3: Setup toolchain ──────────────────────────────────────────
export OHOS_SDK="/storage/Users/currentUser/.harmonybrew/opt/ohos-sdk"
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

git clone --depth 1 https://github.com/openharmony/third_party_bounds_checking_function.git \
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
