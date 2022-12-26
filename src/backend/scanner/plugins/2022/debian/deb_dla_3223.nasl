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
  script_oid("1.3.6.1.4.1.25623.1.0.893223");
  script_version("2022-12-07T10:11:17+0000");
  script_cve_id("CVE-2018-11490", "CVE-2019-15133");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2022-12-06 02:00:30 +0000 (Tue, 06 Dec 2022)");
  script_name("Debian LTS: Security Advisory for giflib (DLA-3223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3223-1");
  script_xref(name:"Advisory-ID", value:"DLA-3223-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/904114");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib'
  package(s) announced via the DLA-3223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes two file format vulnerabilities in giflib.

CVE-2018-11490

The DGifDecompressLine function in dgif_lib.c, as later shipped in
cgif.c in sam2p 0.49.4, has a heap-based buffer overflow because a
certain 'Private->RunningCode - 2' array index is not checked. This
will lead to a denial of service or possibly unspecified other
impact.

CVE-2019-15133

A malformed GIF file triggers a divide-by-zero exception in the
decoder function DGifSlurp in dgif_lib.c if the height field of the
ImageSize data structure is equal to zero.");

  script_tag(name:"affected", value:"'giflib' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.1.4-3+deb10u1.

We recommend that you upgrade your giflib packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"giflib-tools", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgif-dev", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgif7", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
