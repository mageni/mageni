# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892998");
  script_version("2022-05-11T01:00:09+0000");
  script_cve_id("CVE-2022-23803", "CVE-2022-23804", "CVE-2022-23946", "CVE-2022-23947");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 01:00:09 +0000 (Wed, 11 May 2022)");
  script_name("Debian LTS: Security Advisory for kicad (DLA-2998-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2998-1");
  script_xref(name:"Advisory-ID", value:"DLA-2998-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kicad'
  package(s) announced via the DLA-2998-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KiCad is a suite of programs for the creation of printed circuit boards.
It includes a schematic editor, a PCB layout tool, support tools and a 3D
viewer to display a finished & fully populated PCB.

Several buffer-overflows were discovered in the Gerber Viewer and excellon
file parser, that could lead to code execution when opening a
maliciously-crafted file.

CVE-2022-23803

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon ReadXYCoord coordinate parsing functionality of KiCad
EDA.

CVE-2022-23804

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon ReadIJCoord coordinate parsing functionality of KiCad
EDA.

CVE-2022-23946

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon GCodeNumber parsing functionality of KiCad EDA.

CVE-2022-23947

A stack-based buffer overflow vulnerability exists in the Gerber Viewer
gerber and excellon DCodeNumber parsing functionality of KiCad EDA.");

  script_tag(name:"affected", value:"'kicad' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.0.5+dfsg1-4+deb9u1.

We recommend that you upgrade your kicad packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"kicad", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-common", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ca", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-de", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-en", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-es", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-fr", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-it", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ja", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-nl", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-pl", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ru", ver:"4.0.5+dfsg1-4+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
