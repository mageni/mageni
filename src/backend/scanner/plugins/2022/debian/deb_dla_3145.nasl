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
  script_oid("1.3.6.1.4.1.25623.1.0.893145");
  script_version("2022-10-12T10:13:47+0000");
  script_cve_id("CVE-2021-21300", "CVE-2021-40330");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-12 10:13:47 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-05 14:23:00 +0000 (Wed, 05 May 2021)");
  script_tag(name:"creation_date", value:"2022-10-12 01:00:09 +0000 (Wed, 12 Oct 2022)");
  script_name("Debian LTS: Security Advisory for git (DLA-3145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/10/msg00014.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3145-1");
  script_xref(name:"Advisory-ID", value:"DLA-3145-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/985120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the DLA-3145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in Git, a fast, scalable,
distributed revision control system, which may affect multi-user systems.

CVE-2021-21300

A specially crafted repository that contains symbolic links as well as
files using a clean/smudge filter such as Git LFS, may cause just-checked
out script to be executed while cloning onto a case-insensitive file system
such as NTFS, HFS+ or APFS (i.e. the default file systems on Windows and
macOS).

CVE-2021-40330

git_connect_git in connect.c allows a repository path to contain a newline
character, which may result in unexpected cross-protocol requests, as
demonstrated by the git://localhost:1234/%0d%0a%0d%0aGET%20/%20HTTP/1.1
substring.");

  script_tag(name:"affected", value:"'git' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1:2.20.1-2+deb10u4.

We recommend that you upgrade your git packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-all", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-cvs", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-run", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-daemon-sysvinit", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-doc", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-el", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-email", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-gui", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-man", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-mediawiki", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"git-svn", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitk", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gitweb", ver:"1:2.20.1-2+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
