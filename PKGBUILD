# Maintainer: mrkirby153 <mrkirby153@mrkirby153.com>
pkgname=vault-ssh-helper-git
pkgver=r4.7be1230
pkgrel=1
epoch=
pkgdesc="A ssh wrapper for hashicorp vault"
arch=('any')
url="https://github.com/mrkirby153/vault-ssh-helper"
license=('MIT')
makedepends=('cargo' 'git')
provides=('vssh')
conflicts=('vssh')
replaces=()
source=("${pkgname%-git}::git://github.com/mrkirby153/vault-ssh-helper.git")
sha256sums=('SKIP')

pkgver() {
  cd "$srcdir/${pkgname%-git}"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd "$srcdir/${pkgname%-git}"
  cargo build --locked --release --target-dir target
}

package() {
  cd "$srcdir/${pkgname%-git}"
  install -Dm755 target/release/vault-ssh-helper "${pkgdir}/usr/bin/vssh"
}
