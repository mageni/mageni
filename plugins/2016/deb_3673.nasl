# OpenVAS Vulnerability Test
# $Id: deb_3673.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3673-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703673");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180",
                  "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302",
                  "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_name("Debian Security Advisory DSA 3673-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-22 00:00:00 +0200 (Thu, 22 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3673.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 1.0.1t-1+deb8u4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in OpenSSL:

CVE-2016-2177
Guido Vranken discovered that OpenSSL uses undefined pointer
arithmetic.

CVE-2016-2178
Cesar Pereida, Billy Brumley and Yuval Yarom discovered a timing
leak in the DSA code.

CVE-2016-2179 / CVE-2016-2181
Quan Luo and the OCAP audit team discovered denial of service
vulnerabilities in DTLS.

CVE-2016-2180 / CVE-2016-2182 / CVE-2016-6303
Shi Lei discovered an out-of-bounds memory read in
TS_OBJ_print_bio() and an out-of-bounds write in BN_bn2dec()
and MDC2_Update().

CVE-2016-2183
DES-based cipher suites are demoted from the HIGH group to MEDIUM
as a mitigation for the SWEET32 attack.

CVE-2016-6302
Shi Lei discovered that the use of SHA512 in TLS session tickets
is susceptible to denial of service.

CVE-2016-6304
Shi Lei discovered that excessively large OCSP status request may
result in denial of service via memory exhaustion.

CVE-2016-6306
Shi Lei discovered that missing message length validation when parsing
certificates may potentially result in denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev:amd64", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev:i386", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:amd64", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:amd64", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg:i386", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl-dbgsym", ver:"1.0.1t-1+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}