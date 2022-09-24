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
  script_oid("1.3.6.1.4.1.25623.1.0.893113");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2020-35530", "CVE-2020-35531", "CVE-2020-35532", "CVE-2020-35533");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-17 01:00:41 +0000 (Sat, 17 Sep 2022)");
  script_name("Debian LTS: Security Advisory for libraw (DLA-3113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3113-1");
  script_xref(name:"Advisory-ID", value:"DLA-3113-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the DLA-3113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple file parsing vulnerabilities have been fixed in libraw. They are
concerned with the dng and x3f formats.

CVE-2020-35530

There is an out-of-bounds write vulnerability within the 'new_node()'
function (src/x3f/x3f_utils_patched.cpp) that can be triggered via a
crafted X3F file. Reported by github user 0xfoxone.

CVE-2020-35531

An out-of-bounds read vulnerability exists within the
get_huffman_diff() function (src/x3f/x3f_utils_patched.cpp) when
reading data from an image file. Reported by github user GirlElecta.

CVE-2020-35532

An out-of-bounds read vulnerability exists within the
'simple_decode_row()' function (src/x3f/x3f_utils_patched.cpp) which
can be triggered via an image with a large row_stride field.
Reported by github user GirlElecta.

CVE-2020-35533

An out-of-bounds read vulnerability exists within the
'LibRaw::adobe_copy_pixel()' function (src/decoders/dng.cpp) when
reading data from the image file. Reported by github user GirlElecta.");

  script_tag(name:"affected", value:"'libraw' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.19.2-2+deb10u1.

We recommend that you upgrade your libraw packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libraw-bin", ver:"0.19.2-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw-dev", ver:"0.19.2-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw-doc", ver:"0.19.2-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libraw19", ver:"0.19.2-2+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
