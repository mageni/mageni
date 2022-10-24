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
  script_oid("1.3.6.1.4.1.25623.1.0.893152");
  script_version("2022-10-18T10:13:37+0000");
  script_cve_id("CVE-2016-10228", "CVE-2019-19126", "CVE-2019-25013", "CVE-2020-10029", "CVE-2020-1752", "CVE-2020-27618", "CVE-2020-6096", "CVE-2021-27645", "CVE-2021-3326", "CVE-2021-33574", "CVE-2021-35942", "CVE-2021-3999", "CVE-2022-23218", "CVE-2022-23219");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-18 10:13:37 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-07 03:15:00 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-10-18 01:00:17 +0000 (Tue, 18 Oct 2022)");
  script_name("Debian LTS: Security Advisory for glibc (DLA-3152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/10/msg00021.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3152-1");
  script_xref(name:"Advisory-ID", value:"DLA-3152-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/856503");
  script_xref(name:"URL", value:"https://bugs.debian.org/945250");
  script_xref(name:"URL", value:"https://bugs.debian.org/953108");
  script_xref(name:"URL", value:"https://bugs.debian.org/953788");
  script_xref(name:"URL", value:"https://bugs.debian.org/961452");
  script_xref(name:"URL", value:"https://bugs.debian.org/973914");
  script_xref(name:"URL", value:"https://bugs.debian.org/979273");
  script_xref(name:"URL", value:"https://bugs.debian.org/981198");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the DLA-3152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a wide range of vulnerabilities. A significant portion
affects character set conversion.

CVE-2016-10228

The iconv program in the GNU C Library when invoked with multiple
suffixes in the destination encoding (TRANSLATE or IGNORE) along with
the -c option, enters an infinite loop when processing invalid
multi-byte input sequences, leading to a denial of service.

CVE-2019-19126

On the x86-64 architecture, the GNU C Library fails to ignore the
LD_PREFER_MAP_32BIT_EXEC environment variable during program
execution after a security transition, allowing local attackers to
restrict the possible mapping addresses for loaded libraries and
thus bypass ASLR for a setuid program.

CVE-2019-25013

The iconv feature in the GNU C Library, when processing invalid
multi-byte input sequences in the EUC-KR encoding, may have a buffer
over-read.

CVE-2020-10029

The GNU C Library could overflow an on-stack buffer during range
reduction if an input to an 80-bit long double function contains a
non-canonical bit pattern, a seen when passing a
0x5d414141414141410000 value to sinl on x86 targets. This is related
to sysdeps/ieee754/ldbl-96/e_rem_pio2l.c.

CVE-2020-1752

A use-after-free vulnerability introduced in glibc was found in the
way the tilde expansion was carried out. Directory paths containing
an initial tilde followed by a valid username were affected by this
issue. A local attacker could exploit this flaw by creating a
specially crafted path that, when processed by the glob function,
would potentially lead to arbitrary code execution.

CVE-2020-27618

The iconv function in the GNU C Library, when processing invalid
multi-byte input sequences in IBM1364, IBM1371, IBM1388, IBM1390,
and IBM1399 encodings, fails to advance the input state, which could
lead to an infinite loop in applications, resulting in a denial of
service, a different vulnerability from CVE-2016-10228.

CVE-2020-6096

An exploitable signed comparison vulnerability exists in the ARMv7
memcpy() implementation of GNU glibc. Calling memcpy() (on ARMv7
targets that utilize the GNU glibc implementation) with a negative
value for the 'num' parameter results in a signed comparison
vulnerability. If an attacker underflows the 'num' parameter to
memcpy(), this vulnerability could lead to undefined behavior such as
writing to out-of-bounds memory and potentially remote code
execution. Furthermore, this memcpy() implementation allows for
program execution to continue in scenarios where a segmentation fault
or crash should have occurred. The dangers occur in that subsequent
execution and iterations of this code will be executed with this
corrupted data. ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'glibc' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.28-10+deb10u2.

We recommend that you upgrade your glibc packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"glibc-doc", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"glibc-source", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc-dev-bin", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc-l10n", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-amd64", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-dbg", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-dev", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-amd64", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-i386", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-dev-x32", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-i386", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-pic", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-x32", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libc6-xen", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"locales", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"locales-all", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multiarch-support", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nscd", ver:"2.28-10+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
