# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892092");
  script_version("2020-02-01T04:00:08+0000");
  script_cve_id("CVE-2020-0569");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-02-01 04:00:08 +0000 (Sat, 01 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-01 04:00:08 +0000 (Sat, 01 Feb 2020)");
  script_name("Debian LTS: Security Advisory for qtbase-opensource-src (DLA-2092-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/02/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2092-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase-opensource-src'
  package(s) announced via the DLA-2092-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Qt5's plugin loader code as found in qtbase-opensource-src, it was
possible to (side-)load plugins from 'the' local folder in addition to a
system-widely defined library path.");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
5.3.2+dfsg-4+deb8u4.

We recommend that you upgrade your qtbase-opensource-src packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libqt5concurrent5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5dbus5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5network5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5-dev", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5printsupport5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-mysql", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-odbc", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-psql", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-sqlite", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-tds", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5test5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5widgets5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libqt5xml5", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-default", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dbg", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools-dbg", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc-html", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples-dbg", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qtbase5-private-dev", ver:"5.3.2+dfsg-4+deb8u4", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
