#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -ex

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

# debian.*.sh must be run first
if [ "$ARCH" ]; then
	ARCH=":$ARCH"
	unset CC
else
	apt update
fi

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

case "$TSS" in
ibmtss) TSS="libtss-dev";;
tpm2-tss) TSS="libtss2-dev";;
'') echo "Missing TSS!" >&2; exit 1;;
*) [ "$TSS" ] && echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

apt="apt install -y --no-install-recommends"

$apt \
	$CC $TSS \
	asciidoc \
	attr \
	autoconf \
	automake \
	diffutils \
	debianutils \
	docbook-xml \
	docbook-xsl \
	gzip \
	libattr1-dev$ARCH \
	libkeyutils-dev$ARCH \
	libssl-dev$ARCH \
	libtool \
	make \
	openssl \
	pkg-config \
	procps \
	sudo \
	wget \
	xsltproc \
	haveged \
	systemd-sysv \
	acl \
	e2fsprogs \
	keyutils \
	auditd \
	libcap2-bin \
	reiserfsprogs

$apt xxd || $apt vim-common
$apt libengine-gost-openssl1.1$ARCH || true
