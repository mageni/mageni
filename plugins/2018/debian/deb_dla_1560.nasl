###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1560.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1560-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891560");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1560-1] gnutls28 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-05 00:00:00 +0100 (Mon, 05 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00022.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"gnutls28 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.3.30-0+deb8u1. It was found to be more practical to update to the
latest upstream version of the 3.3.x branch since upstream's fixes
were rather invasive and required cipher list changes anyways. This
will facilitate future LTS updates as well.

This change therefore also includes the following major policy
changes, as documented in the NEWS file:

  * ARCFOUR (RC4) and SSL 3.0 are no longer included in the default
priorities list. Those have to be explicitly enabled, e.g., with
a string like 'NORMAL:+ARCFOUR-128' or 'NORMAL:+VERS-SSL3.0',
respectively.

  * The ciphers utilizing HMAC-SHA384 and SHA256 have been removed
from the default priority strings. They are not necessary for
compatibility or other purpose and provide no advantage over
their SHA1 counter-parts, as they all depend on the legacy TLS
CBC block mode.

  * Follow closely RFC5280 recommendations and use UTCTime for dates
prior to 2050.

  * Require strict DER encoding for certificates, OCSP requests,
private keys, CRLs and certificate requests, in order to reduce
issues due to the complexity of BER rules.

  * Refuse to import v1 or v2 certificates that contain extensions.

API and ABI compatibility is retained, however, although new symbols
have been added. Many bugfixes are also included in the upload. See
the provided upstream changelog for more details.

We recommend that you upgrade your gnutls28 packages and do not expect
significant breakage.");
  script_tag(name:"summary", value:"A set of vulnerabilities was discovered in GnuTLS which allowed
attackers to do plain text recovery on TLS connections with certain
cipher types.

CVE-2018-10844

It was found that the GnuTLS implementation of HMAC-SHA-256 was
vulnerable to a Lucky thirteen style attack. Remote attackers
could use this flaw to conduct distinguishing attacks and
plaintext-recovery attacks via statistical analysis of timing data
using crafted packets.

CVE-2018-10845

It was found that the GnuTLS implementation of HMAC-SHA-384 was
vulnerable to a Lucky thirteen style attack. Remote attackers
could use this flaw to conduct distinguishing attacks and plain
text recovery attacks via statistical analysis of timing data
using crafted packets.

CVE-2018-10846

A cache-based side channel in GnuTLS implementation that leads to
plain text recovery in cross-VM attack setting was found. An
attacker could use a combination of 'Just in Time' Prime+probe
attack in combination with Lucky-13 attack to recover plain text
using crafted packets.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls-doc", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-deb0-28", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls28-dbg", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls28-dev", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx28", ver:"3.3.30-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}