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
  script_oid("1.3.6.1.4.1.25623.1.0.892802");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2018-16062", "CVE-2018-16402", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7150", "CVE-2019-7665");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 12:15:00 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2021-11-01 02:00:12 +0000 (Mon, 01 Nov 2021)");
  script_name("Debian LTS: Security Advisory for elfutils (DLA-2802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/10/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2802-1");
  script_xref(name:"Advisory-ID", value:"DLA-2802-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/907562");
  script_xref(name:"URL", value:"https://bugs.debian.org/911083");
  script_xref(name:"URL", value:"https://bugs.debian.org/911413");
  script_xref(name:"URL", value:"https://bugs.debian.org/911414");
  script_xref(name:"URL", value:"https://bugs.debian.org/920909");
  script_xref(name:"URL", value:"https://bugs.debian.org/921880");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils'
  package(s) announced via the DLA-2802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in elfutils, a collection of
utilities and libraries to handle ELF objects.

CVE-2018-16062

dwarf_getaranges in dwarf_getaranges.c in libdw allowed a denial of
service (heap-based buffer over-read) via a crafted file.

CVE-2018-16402

libelf/elf_end.c in allowed to cause a denial of service (double
free and application crash) because it tried to decompress twice.

CVE-2018-18310

An invalid memory address dereference libdwfl allowed a denial of
service (application crash) via a crafted file.

CVE-2018-18520

A use-after-free in recursive ELF ar files allowed a denial of
service (application crash) via a crafted file.

CVE-2018-18521

A divide-by-zero in arlib_add_symbols() allowed a denial of service
(application crash) via a crafted file.

CVE-2019-7150

A segmentation fault could occur due to dwfl_segment_report_module()
not checking whether the dyn data read from a core file is truncated.

CVE-2019-7665

NT_PLATFORM core notes contain a zero terminated string allowed a
denial of service (application crash) via a crafted file.");

  script_tag(name:"affected", value:"'elfutils' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.168-1+deb9u1.

We recommend that you upgrade your elfutils packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"elfutils", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libasm-dev", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libasm1", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdw-dev", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdw1", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libelf-dev", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libelf1", ver:"0.168-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
