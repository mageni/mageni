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
  script_oid("1.3.6.1.4.1.25623.1.0.893240");
  script_version("2022-12-16T02:00:21+0000");
  script_cve_id("CVE-2020-21599", "CVE-2021-35452", "CVE-2021-36408", "CVE-2021-36409", "CVE-2021-36410", "CVE-2021-36411");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-16 02:00:21 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-16 02:00:21 +0000 (Fri, 16 Dec 2022)");
  script_name("Debian LTS: Security Advisory for libde265 (DLA-3240-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3240-1");
  script_xref(name:"Advisory-ID", value:"DLA-3240-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014977");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libde265'
  package(s) announced via the DLA-3240-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in libde265, an open source implementation of the
h.265 video codec, which may result in denial of or have unspecified other
impact.

CVE-2020-21599

libde265 v1.0.4 contains a heap buffer overflow in the
de265_image::available_zscan function, which can be exploited via a crafted
a file.

CVE-2021-35452

An Incorrect Access Control vulnerability exists in libde265 v1.0.8 due to
a SEGV in slice.cc.

CVE-2021-36408

libde265 v1.0.8 contains a Heap-use-after-free in intrapred.h when decoding
file using dec265.

CVE-2021-36409

There is an Assertion `scaling_list_pred_matrix_id_delta==1' failed at
sps.cc:925 in libde265 v1.0.8 when decoding file, which allows attackers to
cause a Denial of Service (DoS) by running the application with a crafted
file or possibly have unspecified other impact.

CVE-2021-36410

A stack-buffer-overflow exists in libde265 v1.0.8 via fallback-motion.cc in
function put_epel_hv_fallback when running program dec265.

CVE-2021-36411

An issue has been found in libde265 v1.0.8 due to incorrect access control.
A SEGV caused by a READ memory access in function derive_boundaryStrength of
deblock.cc has occurred. The vulnerability causes a segmentation fault and
application crash, which leads to remote denial of service.");

  script_tag(name:"affected", value:"'libde265' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.0.3-1+deb10u1.

We recommend that you upgrade your libde265 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.3-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libde265-dev", ver:"1.0.3-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libde265-examples", ver:"1.0.3-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
