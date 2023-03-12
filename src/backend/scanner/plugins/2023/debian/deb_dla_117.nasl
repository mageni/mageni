# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.117");
  script_cve_id("CVE-2011-3193", "CVE-2011-3194");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-117)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-117");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-117");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt4-x11' package(s) announced via the DLA-117 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2011-3193

Check for buffer overflow in Lookup_MarkMarkPos that may cause crash in this function with certain fonts.

CVE-2011-3194

Fix tiff reader to handle TIFFTAG_SAMPLESPERPIXEL for grayscale images. The reader uses QImage::Format_Indexed8, but since the samples per pixel value this should be (non-existent) QImage::Format_Indexed16, causing memory corruption. The fix falls back to the normal way of reading tiff images.

For Debian 6 Squeeze, these issues have been fixed in qt4-x11 version 4:4.6.3-4+squeeze2");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-assistant", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-core", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbg", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dbus", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-designer", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-dev", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-gui", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-help", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-multimedia", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-network", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl-dev", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-opengl", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-phonon", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-qt3support", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-script", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-scripttools", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-ibase", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-mysql", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-odbc", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-psql", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite2", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-sqlite", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql-tds", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-sql", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-svg", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-test", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit-dbg", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-webkit", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xml", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns-dbg", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt4-xmlpatterns", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtcore4", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqtgui4", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-demos-dbg", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-demos", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-designer", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-dev-tools", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc-html", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-doc", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qmake", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt4-qtconfig", ver:"4:4.6.3-4+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
