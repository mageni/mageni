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
  script_oid("1.3.6.1.4.1.25623.1.0.891865");
  script_version("2019-07-28T02:00:18+0000");
  script_cve_id("CVE-2018-3977", "CVE-2019-12216", "CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-7635");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-28 02:00:18 +0000 (Sun, 28 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-28 02:00:18 +0000 (Sun, 28 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1865-1] sdl-image1.2 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00026.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1865-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sdl-image1.2'
  package(s) announced via the DSA-1865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following issues have been found in sdl-image1.2, the 1.x version of the
image file loading library.

CVE-2018-3977

Heap buffer overflow in IMG_xcf.c. This vulnerability might be leveraged by
remote attackers to cause remote code execution or denial of service via a
crafted XCF file.

CVE-2019-5051

Heap based buffer overflow in IMG_LoadPCX_RW, in IMG_pcx.c. This
vulnerability might be leveraged by remote attackers to cause remote code
execution or denial of service via a crafted PCX file.

CVE-2019-5052

Integer overflow and subsequent buffer overflow in IMG_pcx.c. This
vulnerability might be leveraged by remote attackers to cause remote code
execution or denial of service via a crafted PCX file.

CVE-2019-7635

Heap buffer overflow affecting Blit1to4, in IMG_bmp.c. This vulnerability
might be leveraged by remote attackers to cause denial of service or any
other unspecified impact via a crafted BMP file.

CVE-2019-12216,
CVE-2019-12217,
CVE-2019-12218,
CVE-2019-12219,
CVE-2019-12220,
CVE-2019-12221,
CVE-2019-12222

Multiple out-of-bound read and write accesses affecting IMG_LoadPCX_RW, in
IMG_pcx.c. These vulnerabilities might be leveraged by remote attackers to
cause denial of service or any other unspecified impact via a crafted PCX
file.");

  script_tag(name:"affected", value:"'sdl-image1.2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.2.12-5+deb8u2.

We recommend that you upgrade your sdl-image1.2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";

# nb: Announcement thread mentions 1.2.12-5+deb9u2 as fixed but the actual fixed version is 1.2.12-5+deb8u2
if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2", ver:"1.2.12-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2-dbg", ver:"1.2.12-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsdl-image1.2-dev", ver:"1.2.12-5+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);