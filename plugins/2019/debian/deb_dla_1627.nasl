###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1627.nasl 14274 2019-03-18 14:38:37Z cfischer $
#
# Auto-generated from advisory DLA 1627-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.891627");
  script_version("$Revision: 14274 $");
  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1627-1] qtbase-opensource-src security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:38:37 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-03 00:00:00 +0100 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00004.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"qtbase-opensource-src on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
5.3.2+dfsg-4+deb8u3.

We recommend that you upgrade your qtbase-opensource-src packages.");
  script_tag(name:"summary", value:"Multiple issues were fixed in Qt.

CVE-2018-15518
A double-free or corruption during parsing of a specially crafted
illegal XML document.

CVE-2018-19870
A malformed GIF image might have caused a NULL pointer dereference in
QGifHandler resulting in a segmentation fault.

CVE-2018-19873
QBmpHandler had a buffer overflow via BMP data.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libqt5concurrent5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5dbus5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5network5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5opengl5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5opengl5-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5printsupport5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5-mysql", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5-odbc", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5-psql", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5-sqlite", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5sql5-tds", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5test5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5widgets5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libqt5xml5", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qt5-default", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qt5-qmake", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-dev-tools", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-dev-tools-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-doc-html", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-examples", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-examples-dbg", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qtbase5-private-dev", ver:"5.3.2+dfsg-4+deb8u3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}