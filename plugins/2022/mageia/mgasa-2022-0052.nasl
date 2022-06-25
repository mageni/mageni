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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0052");
  script_cve_id("CVE-2021-3999");
  script_tag(name:"creation_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T07:40:33+0000");
  script_tag(name:"last_modification", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0052");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0052.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29935");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2022-0052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glibc packages fix security vulnerability:

An off-by-one buffer overflow and underflow in getcwd() may lead to memory
corruption when the size of the buffer is exactly 1. A local attacker who
can control the input buffer and size passed to getcwd() in a setuid program
could use this flaw to potentially execute arbitrary code and escalate their
privileges on the system (CVE-2021-3999).

Other upstream fixes in this update:
- gconv: Do not emit spurious NUL character in ISO-2022-JP-3 [BZ #28524]
- x86: Fix __wcsncmp_avx2 in strcmp-avx2.S [BZ #28755]
- x86: Set Prefer_No_VZEROUPPER and add Prefer_AVX2_STRCMP
- x86-64: Add ifunc-avx2.h functions with 256-bit EVEX
- x86-64: Add strcpy family functions with 256-bit EVEX
- x86-64: Add memmove family functions with 256-bit EVEX
- x86-64: Add memset family functions with 256-bit EVEX
- x86-64: Add memcmp family functions with 256-bit EVEX
- x86-64: Add AVX optimized string/memory functions for RTM
- x86: Add string/memory function tests in RTM region
- x86-64: Use ZMM16-ZMM31 in AVX512 memset family functions
- x86-64: Use ZMM16-ZMM31 in AVX512 memmove family functions
- test-strnlen.c: Initialize wchar_t string with wmemset [BZ #27655]
- test-strnlen.c: Check that strnlen won't go beyond the maximum length
- x86: Optimize memchr-avx2.S
- x86: Fix overflow bug with wmemchr-sse2 and wmemchr-avx2 [BZ #27974]
- x86: Optimize strlen-avx2.S
- x86: Optimize memchr-evex.S
- x86-64: Fix an unknown vector operation in memchr-evex.S
- x86-64: Move strlen.S to multiarch/strlen-vec.S
- x86-64: Add wcslen optimize for sse4.1
- x86: Fix overflow bug in wcsnlen-sse4_1 and wcsnlen-avx2 [BZ #27974]
- x86: Optimize strlen-evex.S
- String: Add overflow tests for strnlen, memchr, and strncat [BZ #27974]
- x86-64: Require BMI2 for __strlen_evex and __strnlen_evex
- x86: Check RTM_ALWAYS_ABORT for RTM [BZ #28033]
- x86: Black list more Intel CPUs for TSX [BZ #27398]
- x86: Remove wcsnlen-sse4_1 from wcslen ifunc-impl-list [BZ #28064]
- x86-64: Test strlen and wcslen with 0 in the RSI register [BZ #28064]");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.32~25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.32~25.mga8", rls:"MAGEIA8"))) {
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
