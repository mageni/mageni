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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0053");
  script_cve_id("CVE-2019-25013", "CVE-2020-29562", "CVE-2020-6096");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 20:46:00 +0000 (Thu, 04 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0053");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0053.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28161");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4Y6TX47P47KABSFOL26FLDNVCWXDKDEZ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2021-0053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fixes:
- fix buffer overrun in EUC-KR conversion module [bz #2497] (CVE-2019-25013)
- arm: CVE-2020-6096: Fix multiarch memcpy for negative length [BZ #25620]
- arm: CVE-2020-6096: fix memcpy and memmove for negative length [BZ #25620]
- iconv: Fix incorrect UCS4 inner loop bounds [BZ #26923] (CVE-2020-29562)
other upstream fixes:
- libio: Disable vtable validation for pre-2.1 interposed handles [BZ #25203]
- string.h: Define __CORRECT_ISO_CPP_STRING_H_PROTO for Clang [BZ #25232]
- misc/test-errno-linux: Handle EINVAL from quotactl
- nss_compat: internal_end*ent may clobber errno, hiding ERANGE [BZ #25976]
- Fix avx2 strncmp offset compare condition check [BZ #25933]
- AArch64: Align ENTRY to a cacheline
- AArch64: Add optimized Q-register memcpy
- AArch64: Improve backwards memmove performance
- AArch64: Rename IS_ARES to IS_NEOVERSE_N1
- AArch64: Increase small and medium cases for __memcpy_generic
- AArch64: Improve integer memcpy
- AArch64: Use __memcpy_simd on Neoverse N2/V1
- AArch64: Fix DT_AARCH64_VARIANT_PCS handling [BZ #26798]
- AArch64: fix stack missing after sp is updated
- x86-64: Avoid rep movsb with short distance [BZ #27130]
- x86: Assume --enable-cet if GCC defaults to CET [BZ #25225]
- x86: Check IFUNC definition in unrelocated executable [BZ #20019]
- x86: Set header.feature_1 in TCB for always-on CET [BZ #27177]
- Fix parsing of /sys/devices/system/cpu/online [BZ #25859]
- Use O_CLOEXEC in sysconf [BZ #26791]");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.29~21.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.29~21.mga7", rls:"MAGEIA7"))) {
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
