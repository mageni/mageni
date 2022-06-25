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
  script_oid("1.3.6.1.4.1.25623.1.0.892947");
  script_version("2022-03-15T03:03:42+0000");
  script_cve_id("CVE-2021-3872", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3973", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4192", "CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0319", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0368", "CVE-2022-0408", "CVE-2022-0554", "CVE-2022-0685", "CVE-2022-0714", "CVE-2022-0729");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-24 03:15:00 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2022-03-12 02:00:30 +0000 (Sat, 12 Mar 2022)");
  script_name("Debian LTS: Security Advisory for vim (DLA-2947-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/03/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2947-1");
  script_xref(name:"Advisory-ID", value:"DLA-2947-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the DLA-2947-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in vim, an
enhanced vi editor. Buffer overflows, out-of-bounds reads and Null pointer
dereferences may lead to a denial of service (application crash) or other
unspecified impact.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2:8.0.0197-4+deb9u5.

We recommend that you upgrade your vim packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.0.0197-4+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
