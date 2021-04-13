#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

case "$TSS" in
ibmtss) TSS="ibmtss-devel";;
tpm2-tss) TSS="tpm2-0-tss-devel";;
'') echo "Missing TSS!" >&2; exit 1;;
*) echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

# clang has some gcc dependency
[ "$CC" = "gcc" ] || CC="gcc $CC"

zypper --non-interactive install --force-resolution --no-recommends \
	$CC $TSS \
	asciidoc \
	attr \
	autoconf \
	automake \
	diffutils \
	docbook_5 \
	docbook5-xsl-stylesheets \
	gzip \
	ibmswtpm2 \
	keyutils-devel \
	libattr-devel \
	libopenssl-devel \
	libtool \
	make \
	openssl \
	pkg-config \
	procps \
	sudo \
	vim \
	wget \
	which \
	xsltproc \
	curl \
	haveged \
	systemd-sysvinit \
	e2fsprogs \
	keyutils \
	acl \
	libcap-progs \
	reiserfs \
	ocfs2-tools \
	ocfs2-tools-o2cb \
	iproute2

zypper --non-interactive install --force-resolution --no-recommends \
	gnutls openssl-engine-libp11 softhsm || true

wget https://download.opensuse.org/repositories/home:/mkubecek:/utils/openSUSE_Factory_ARM/noarch/insserv-compat-0.1-2.1.noarch.rpm

rpm -Uhvi insserv-compat-0.1-2.1.noarch.rpm

if [ -f /usr/lib/ibmtss/tpm_server -a ! -e /usr/local/bin/tpm_server ]; then
	ln -s /usr/lib/ibmtss/tpm_server /usr/local/bin
fi

mkdir -p /etc/ocfs2

cat >/etc/ocfs2/cluster.conf <<EOF
cluster:
	node_count = 1
	name = ocfs2

node:
	ip_port = 7777
	ip_address = 127.0.0.1
	number = 0
	name = linux-uml
	cluster = ocfs2
EOF
