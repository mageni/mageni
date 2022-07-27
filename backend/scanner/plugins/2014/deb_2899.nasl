# OpenVAS Vulnerability Test
# $Id: deb_2899.nasl 14277 2019-03-18 14:45:38Z cfischer $
# Auto-generated from advisory DSA 2899-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702899");
  script_version("$Revision: 14277 $");
  script_cve_id("CVE-2014-0159", "CVE-2014-2852");
  script_name("Debian Security Advisory DSA 2899-1 (openafs - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-09 00:00:00 +0200 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2899.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"openafs on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze),
this problem has been fixed in version 1.4.12.1+dfsg-4+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.1-3+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.7-1.

We recommend that you upgrade your openafs packages.");
  script_tag(name:"summary", value:"Michael Meffie discovered that in
OpenAFS, a distributed filesystem, an attacker with the ability to connect to
an OpenAFS fileserver can trigger a buffer overflow, crashing the fileserver,
and potentially permitting the execution of arbitrary code.

In addition, this update addresses a minor denial of service issue:
the listener thread of the server will hang for about one second when
receiving an invalid packet, giving the opportunity to slow down
the server to an unusable state by sending such packets.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-modules-dkms", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.12.1+dfsg-4+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libafsauthent1", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libafsrpc1", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkopenafs1", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-client", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-doc", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-fuse", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-modules-dkms", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.6.1-3+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}