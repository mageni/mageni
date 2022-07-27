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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0011");
  script_cve_id("CVE-2020-16592", "CVE-2020-16598");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-15 11:15:00 +0000 (Fri, 15 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0011");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0011.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27954");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DJIW6KKY2TSLD43XEZXG56WREIIBUIIQ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils, cross-binutils, mingw-binutils' package(s) announced via the MGASA-2021-0011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mingw-binutils and binutils suffered from two
vulnerabilities which might lead to DoS.

Null Pointer Dereference in debug_get_real_type could result in DoS
(CVE-2020-16598).

Use-after-free in bfd_hash_lookup could result in DoS (CVE-2020-16592).");

  script_tag(name:"affected", value:"'binutils, cross-binutils, mingw-binutils' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.33.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-aarch64-linux-gnu", rpm:"binutils-aarch64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-alpha-linux-gnu", rpm:"binutils-alpha-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-arc-linux-gnu", rpm:"binutils-arc-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-arm-linux-gnu", rpm:"binutils-arm-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-avr32-linux-gnu", rpm:"binutils-avr32-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-bfin-linux-gnu", rpm:"binutils-bfin-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-c6x-linux-gnu", rpm:"binutils-c6x-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-cris-linux-gnu", rpm:"binutils-cris-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-frv-linux-gnu", rpm:"binutils-frv-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-h8300-linux-gnu", rpm:"binutils-h8300-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-hppa-linux-gnu", rpm:"binutils-hppa-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-hppa64-linux-gnu", rpm:"binutils-hppa64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-ia64-linux-gnu", rpm:"binutils-ia64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-m32r-linux-gnu", rpm:"binutils-m32r-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-m68k-linux-gnu", rpm:"binutils-m68k-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-metag-linux-gnu", rpm:"binutils-metag-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-microblaze-linux-gnu", rpm:"binutils-microblaze-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-mips64-linux-gnu", rpm:"binutils-mips64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-mn10300-linux-gnu", rpm:"binutils-mn10300-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-nios2-linux-gnu", rpm:"binutils-nios2-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-openrisc-linux-gnu", rpm:"binutils-openrisc-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-powerpc64-linux-gnu", rpm:"binutils-powerpc64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-powerpc64le-linux-gnu", rpm:"binutils-powerpc64le-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-ppc64-linux-gnu", rpm:"binutils-ppc64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-ppc64le-linux-gnu", rpm:"binutils-ppc64le-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-riscv64-linux-gnu", rpm:"binutils-riscv64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-s390x-linux-gnu", rpm:"binutils-s390x-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-score-linux-gnu", rpm:"binutils-score-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-sh-linux-gnu", rpm:"binutils-sh-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-sparc64-linux-gnu", rpm:"binutils-sparc64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-tile-linux-gnu", rpm:"binutils-tile-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-x86_64-linux-gnu", rpm:"binutils-x86_64-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"binutils-xtensa-linux-gnu", rpm:"binutils-xtensa-linux-gnu~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-binutils", rpm:"cross-binutils~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cross-binutils-common", rpm:"cross-binutils-common~2.31.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.33.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.33.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils", rpm:"mingw-binutils~2.30~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-generic", rpm:"mingw-binutils-generic~2.30~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-binutils", rpm:"mingw32-binutils~2.30~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-binutils", rpm:"mingw64-binutils~2.30~3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
