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
  script_oid("1.3.6.1.4.1.25623.1.0.893204");
  script_version("2022-11-25T10:12:49+0000");
  script_cve_id("CVE-2022-0318", "CVE-2022-0392", "CVE-2022-0629", "CVE-2022-0696", "CVE-2022-1619", "CVE-2022-1621", "CVE-2022-1785", "CVE-2022-1897", "CVE-2022-1942", "CVE-2022-2000", "CVE-2022-2129", "CVE-2022-3235", "CVE-2022-3256", "CVE-2022-3352");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-11-25 10:12:49 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:17:00 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-11-25 02:00:19 +0000 (Fri, 25 Nov 2022)");
  script_name("Debian LTS: Security Advisory for vim (DLA-3204-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00032.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3204-1");
  script_xref(name:"Advisory-ID", value:"DLA-3204-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the DLA-3204-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes multiple memory access violations in vim.

CVE-2022-0318

Heap-based Buffer Overflow

CVE-2022-0392

Heap-based Buffer Overflow

CVE-2022-0629

Stack-based Buffer Overflow

CVE-2022-0696

NULL Pointer Dereference

CVE-2022-1619

Heap-based Buffer Overflow in function cmdline_erase_chars. These
vulnerabilities are capable of crashing software, modify memory, and
possible remote execution

CVE-2022-1621

Heap buffer overflow in vim_strncpy find_word. This vulnerability is
capable of crashing software, Bypass Protection Mechanism, Modify
Memory, and possible remote execution

CVE-2022-1785

Out-of-bounds Write

CVE-2022-1897

Out-of-bounds Write

CVE-2022-1942

Heap-based Buffer Overflow

CVE-2022-2000

Out-of-bounds Write

CVE-2022-2129

Out-of-bounds Write

CVE-2022-3235

Use After Free

CVE-2022-3256

Use After Free

CVE-2022-3352

Use After Free");

  script_tag(name:"affected", value:"'vim' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2:8.1.0875-5+deb10u4.

We recommend that you upgrade your vim packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.1.0875-5+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
