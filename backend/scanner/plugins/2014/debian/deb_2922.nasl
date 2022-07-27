# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 2922-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.702922");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2014-2891");
  script_name("Debian Security Advisory DSA 2922-1 (strongswan - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2014-05-05 00:00:00 +0200 (Mon, 05 May 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2922.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"strongswan on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.6.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u4.

For the testing distribution (jessie), this problem has been fixed in
version 5.1.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 5.1.2-1.

We recommend that you upgrade your strongswan packages.");
  script_tag(name:"summary", value:"A vulnerability has been found in the ASN.1 parser of strongSwan, an
IKE/IPsec suite used to establish IPsec protected links.

By sending a crafted ID_DER_ASN1_DN ID payload to a vulnerable pluto or
charon daemon, a malicious remote user can provoke a null pointer
dereference in the daemon parsing the identity, leading to a crash and a
denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.4.1-5.6", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.5.2-1.5+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}