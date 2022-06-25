# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3500-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703500");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2015-7575", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_name("Debian Security Advisory DSA 3500-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2016-03-08 12:37:52 +0530 (Tue, 08 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3500.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 1.0.1e-2+deb7u20.

For the stable distribution (jessie), these problems have been fixed in
version 1.0.1k-3+deb8u4.

For the unstable distribution (sid), these problems will be fixed shortly.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in OpenSSL, a Secure Socket Layer
toolkit.

CVE-2016-0702
Yuval Yarom from the University of Adelaide and NICTA, Daniel Genkin
from Technion and Tel Aviv University, and Nadia Heninger from the
University of Pennsylvania discovered a side-channel attack which
makes use of cache-bank conflicts on the Intel Sandy-Bridge
microarchitecture. This could allow local attackers to recover RSA
private keys.

CVE-2016-0705
Adam Langley from Google discovered a double free bug when parsing
malformed DSA private keys. This could allow remote attackers to
cause a denial of service or memory corruption in applications
parsing DSA private keys received from untrusted sources.

CVE-2016-0797
Guido Vranken discovered an integer overflow in the BN_hex2bn and
BN_dec2bn functions that can lead to a NULL pointer dereference and
heap corruption. This could allow remote attackers to cause a denial
of service or memory corruption in applications processing hex or
dec data received from untrusted sources.

CVE-2016-0798
Emilia Kasper of the OpenSSL development team discovered a memory
leak in the SRP database lookup code. To mitigate the memory leak,
the seed handling in SRP_VBASE_get_by_user is now disabled even if
the user has configured a seed. Applications are advised to migrate
to the SRP_VBASE_get1_by_user function.

CVE-2016-0799
Guido Vranken discovered an integer overflow in the BIO_*printf
functions that could lead to an OOB read when printing very long
strings. Additionally the internal doapr_outch function can attempt
to write to an arbitrary memory location in the event of a memory
allocation failure. These issues will only occur on platforms where
sizeof(size_t)> sizeof(int) like many 64 bit systems. This could
allow remote attackers to cause a denial of service or memory
corruption in applications that pass large amounts of untrusted data
to the BIO_*printf functions.

Additionally the EXPORT and LOW ciphers were disabled since they could
be used as part of the DROWN (CVE-2016-0800) and SLOTH (CVE-2015-7575)
attacks, but note that the oldstable (wheezy) and stable (jessie)
distributions are not affected by those attacks since the SSLv2 protocol
has already been dropped in the openssl package version 1.0.0c-2.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl-dbgsym", ver:"1.0.1k-3+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
