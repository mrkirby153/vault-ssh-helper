# Maintainer: mrkirby153 <mrkirby153@mrkirby153.com>
pkgname=vault-ssh-helper-git
pkgver=r17.27887da
pkgrel=1
epoch=
pkgdesc="A ssh wrapper for hashicorp vault"
arch=('any')
url="https://github.com/mrkirby153/vault-ssh-helper"
license=('MIT')
depends=('openssh')
makedepends=('cargo' 'git')
provides=('vssh')
conflicts=('vssh')
replaces=()
source=("${pkgname%-git}::git+https://github.com/mrkirby153/vault-ssh-helper.git")
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
  install -Dm644 completions/_vssh "${pkgdir}/usr/share/zsh/site-functions/_vssh"
}
