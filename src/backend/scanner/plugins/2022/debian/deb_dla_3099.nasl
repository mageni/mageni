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
  script_oid("1.3.6.1.4.1.25623.1.0.893099");
  script_version("2022-09-06T10:10:57+0000");
  script_cve_id("CVE-2020-13253", "CVE-2020-15469", "CVE-2020-15859", "CVE-2020-25084", "CVE-2020-25085", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-27617", "CVE-2020-27821", "CVE-2020-28916", "CVE-2020-29129", "CVE-2020-29443", "CVE-2020-35504", "CVE-2020-35505", "CVE-2021-20181", "CVE-2021-20196", "CVE-2021-20203", "CVE-2021-20221", "CVE-2021-20257", "CVE-2021-3392", "CVE-2021-3416", "CVE-2021-3507", "CVE-2021-3527", "CVE-2021-3582", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3682", "CVE-2021-3713", "CVE-2021-3748", "CVE-2021-3930", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-26354", "CVE-2022-35414");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-06 10:10:57 +0000 (Tue, 06 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 18:58:00 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-09-06 01:00:36 +0000 (Tue, 06 Sep 2022)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-3099-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3099-1");
  script_xref(name:"Advisory-ID", value:"DLA-3099-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-3099-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in QEMU, a fast processor
emulator, which could result in denial of service or the execution
of arbitrary code.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1:3.1+dfsg-8+deb10u9.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-data", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-gui", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:3.1+dfsg-8+deb10u9", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
