# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892772");
  script_version("2021-10-01T08:01:29+0000");
  script_cve_id("CVE-2017-12678", "CVE-2018-11439");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-01 10:33:46 +0000 (Fri, 01 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-14 18:53:00 +0000 (Wed, 14 Oct 2020)");
  script_tag(name:"creation_date", value:"2021-10-01 01:00:28 +0000 (Fri, 01 Oct 2021)");
  script_name("Debian LTS: Security Advisory for taglib (DLA-2772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/09/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2772-1");
  script_xref(name:"Advisory-ID", value:"DLA-2772-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/871511");
  script_xref(name:"URL", value:"https://bugs.debian.org/903847");
  script_xref(name:"URL", value:"https://bugs.debian.org/915281");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'taglib'
  package(s) announced via the DLA-2772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems were corrected in TagLib,
a library for reading and editing audio meta data.

CVE-2017-12678

A crafted audio file could result in a crash.

CVE-2018-11439

A crafted audio file could result in information disclosure.

Additionally, a bug that can lead to corruption of ogg files
has been fixed.");

  script_tag(name:"affected", value:"'taglib' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.11.1+dfsg.1-0.3+deb9u1.

We recommend that you upgrade your taglib packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtag1-dev", ver:"1.11.1+dfsg.1-0.3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtag1v5", ver:"1.11.1+dfsg.1-0.3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtag1v5-vanilla", ver:"1.11.1+dfsg.1-0.3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtagc0", ver:"1.11.1+dfsg.1-0.3+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtagc0-dev", ver:"1.11.1+dfsg.1-0.3+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
