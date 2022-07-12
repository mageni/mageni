# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891786");
  script_version("2019-05-15T02:00:11+0000");
  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19873");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-15 02:00:11 +0000 (Wed, 15 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-15 02:00:11 +0000 (Wed, 15 May 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1786-1] qt4-x11 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00014.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1786-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/923003");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4-x11'
  package(s) announced via the DSA-1786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been addressed in Qt4.

CVE-2018-15518

A double-free or corruption during parsing of a specially crafted
illegal XML document.

CVE-2018-19869

A malformed SVG image could cause a segmentation fault in
qsvghandler.cpp.

CVE-2018-19870

A malformed GIF image might have caused a NULL pointer dereference in
QGifHandler resulting in a segmentation fault.

CVE-2018-19871

There was an uncontrolled resource consumption in QTgaFile.

CVE-2018-19873

QBmpHandler had a buffer overflow via BMP data.");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2.

We recommend that you upgrade your qt4-x11 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-folderlistmodel", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-gestures", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-particles", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-declarative-shaders", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev-bin", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-gui", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-help", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-phonon", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-private-dev", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-script", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-script-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-scripttools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-ibase", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-tds", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-svg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-test", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-xml", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqtcore4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqtdbus4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qdbus", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-bin-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-default", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-demos", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-demos-dbg", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-designer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-doc", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-linguist-tools", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-qmake", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-qmlviewer", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtcore4-l10n", ver:"4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);