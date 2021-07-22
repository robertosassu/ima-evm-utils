#!/bin/sh
# Copyright (c) 2020 Petr Vorel <pvorel@suse.cz>
set -e

if [ -z "$CC" ]; then
	echo "missing \$CC!" >&2
	exit 1
fi

case "$TSS" in
ibmtss) TSS="tss2-devel";;
tpm2-tss) TSS="tpm2-tss-devel";;
'') echo "Missing TSS!" >&2; exit 1;;
*) echo "Unsupported TSS: '$TSS'!" >&2; exit 1;;
esac

# ibmswtpm2 requires gcc
[ "$CC" = "gcc" ] || CC="gcc $CC"

. /etc/os-release

# EPEL required for haveged
if [ "$PRETTY_NAME" = "CentOS Linux 8" ]; then
	yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
fi

yum -y install \
	$CC $TSS \
	asciidoc \
	attr \
	autoconf \
	automake \
	diffutils \
	docbook-xsl \
	gzip \
	keyutils-libs-devel \
	libattr-devel \
	libtool \
	libxslt \
	make \
	openssl \
	openssl-devel \
	pkg-config \
	procps \
	sudo \
	vim-common \
	wget \
	which \
	curl \
	haveged \
	systemd

yum -y install docbook5-style-xsl || true
yum -y install swtpm || true
