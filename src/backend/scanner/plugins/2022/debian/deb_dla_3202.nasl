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
  script_oid("1.3.6.1.4.1.25623.1.0.893202");
  script_version("2022-11-24T10:18:54+0000");
  script_cve_id("CVE-2019-19221", "CVE-2021-23177", "CVE-2021-31566");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 02:15:00 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2022-11-24 02:00:13 +0000 (Thu, 24 Nov 2022)");
  script_name("Debian LTS: Security Advisory for libarchive (DLA-3202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3202-1");
  script_xref(name:"Advisory-ID", value:"DLA-3202-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/945287");
  script_xref(name:"URL", value:"https://bugs.debian.org/1001986");
  script_xref(name:"URL", value:"https://bugs.debian.org/1001990");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive'
  package(s) announced via the DLA-3202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three issues have been found in libarchive, a multi-format archive and
compression library.

CVE-2019-19221

out-of-bounds read because of an incorrect mbrtowc or mbtowc call

CVE-2021-23177

extracting a symlink with ACLs modifies ACLs of target

CVE-2021-31566

symbolic links incorrectly followed when changing modes, times,
ACL and flags of a file while extracting an archive");

  script_tag(name:"affected", value:"'libarchive' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
3.3.3-4+deb10u2.

We recommend that you upgrade your libarchive packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bsdcpio", ver:"3.3.3-4+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bsdtar", ver:"3.3.3-4+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libarchive-dev", ver:"3.3.3-4+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libarchive-tools", ver:"3.3.3-4+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.3.3-4+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
