# OpenVAS Vulnerability Test
# $Id: deb_3866.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3866-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703866");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2017-9022", "CVE-2017-9023");
  script_name("Debian Security Advisory DSA 3866-1 (strongswan - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-30 00:00:00 +0200 (Tue, 30 May 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3866.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"strongswan on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 5.2.1-6+deb8u3.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 5.5.1-4

For the unstable distribution (sid), these problems have been fixed in
version 5.5.1-4.

We recommend that you upgrade your strongswan packages.");
  script_tag(name:"summary", value:"Two denial of service vulnerabilities were identified in strongSwan, an
IKE/IPsec suite, using Google's OSS-Fuzz fuzzing project.

CVE-2017-9022
RSA public keys passed to the gmp plugin aren't validated sufficiently
before attempting signature verification, so that invalid input might
lead to a floating point exception and crash of the process.
A certificate with an appropriately prepared public key sent by a peer
could be used for a denial-of-service attack.

CVE-2017-9023
ASN.1 CHOICE types are not correctly handled by the ASN.1 parser when
parsing X.509 certificates with extensions that use such types. This could
lead to infinite looping of the thread parsing a specifically crafted
certificate.

A fix for a build failure was additionally included in the 5.2.1-6+deb8u4
revision of the strongSwan package.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"charon-cmd", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ike", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.2.1-6+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"charon-cmd", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"charon-systemd", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ike", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.5.1-", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}