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
  script_oid("1.3.6.1.4.1.25623.1.0.893060");
  script_version("2022-06-30T09:43:30+0000");
  script_cve_id("CVE-2022-0544", "CVE-2022-0545", "CVE-2022-0546");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-30 09:43:30 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 20:34:00 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-06-29 01:00:20 +0000 (Wed, 29 Jun 2022)");
  script_name("Debian LTS: Security Advisory for blender (DLA-3060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00021.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3060-1");
  script_xref(name:"Advisory-ID", value:"DLA-3060-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender'
  package(s) announced via the DLA-3060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in blender, a very fast and versatile 3D
modeller/renderer.

CVE-2022-0546

An out-of-bounds heap access due to missing checks in the image
loader could result in denial of service, memory corruption or
potentially code execution.

CVE-2022-0545

An integer overflow while processing 2d images might result in a
write-what-where vulnerability or an out-of-bounds read vulnerability
which could leak sensitive information or achieve code execution.

CVE-2022-0544

Crafted DDS image files could create an integer underflow in the
DDS loader which leads to an out-of-bounds read and might leak
sensitive information.");

  script_tag(name:"affected", value:"'blender' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.79.b+dfsg0-1~deb9u2.

We recommend that you upgrade your blender packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"blender", ver:"2.79.b+dfsg0-1~deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"blender-data", ver:"2.79.b+dfsg0-1~deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"blender-dbg", ver:"2.79.b+dfsg0-1~deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
