###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4043.nasl 14284 2019-03-18 15:02:15Z cfischer $
#
# Auto-generated from advisory DSA 4043-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704043");
  script_version("$Revision: 14284 $");
  script_cve_id("CVE-2017-14746", "CVE-2017-15275");
  script_name("Debian Security Advisory DSA 4043-1 (samba - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:02:15 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-21 00:00:00 +0100 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4043.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"samba on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 2:4.2.14+dfsg-0+deb8u9.

For the stable distribution (stretch), these problems have been fixed in
version 2:4.5.12+dfsg-2+deb9u1.

We recommend that you upgrade your samba packages.

For the detailed security status of samba  please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/samba");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in Samba, a SMB/CIFS file,
print, and login server for Unix. The Common Vulnerabilities and
Exposures project identifies the following issues:

CVE-2017-14746
Yihan Lian and Zhibin Hu of Qihoo 360 GearTeam discovered a
use-after-free vulnerability allowing a client to compromise a SMB
server via malicious SMB1 requests.

CVE-2017-15275
Volker Lendecke of SerNet and the Samba team discovered that Samba
is prone to a heap memory information leak, where server allocated
heap memory may be returned to the client without being cleared.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ctdb", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-samba", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:4.5.12+dfsg-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ctdb", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-winbind", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-winbind", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libparse-pidl-perl", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-samba", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"registry-tools", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dev", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-doc", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-dsdb-modules", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-libs", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-testsuite", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"samba-vfs-modules", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"smbclient", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"winbind", ver:"2:4.2.14+dfsg-0+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}