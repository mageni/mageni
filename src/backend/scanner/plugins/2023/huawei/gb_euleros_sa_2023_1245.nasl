# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1245");
  script_cve_id("CVE-2018-10534", "CVE-2018-10535", "CVE-2021-3487", "CVE-2021-3549", "CVE-2021-42574", "CVE-2021-45078");
  script_tag(name:"creation_date", value:"2023-01-31 04:21:24 +0000 (Tue, 31 Jan 2023)");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 15:16:00 +0000 (Tue, 16 Nov 2021)");

  script_name("Huawei EulerOS: Security Advisory for bindutils (EulerOS-SA-2023-1245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1245");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1245");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'bindutils' package(s) announced via the EulerOS-SA-2023-1245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system availability by way of excessive memory consumption.(CVE-2021-3487)
An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through 14.0. It permits the visual reordering of characters via control sequences, which can be used to craft source code that renders different logic than the logical ordering of tokens ingested by compilers and interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such that targeted vulnerabilities are introduced invisibly to human reviewers.(CVE-2021-42574
)
An out-of-bounds flaw was found in binutils' stabs functionality. The attack needs to be initiated locally where an attacker could convince a victim to read a specially crafted file that is processed by objdump, leading to the disclosure of memory and possibly leading to the execution of arbitrary code or causing the utility to crash.(CVE-2021-45078)
An out of bounds flaw was found in GNU binutils objdump utility version 2.36. An attacker could use this flaw and pass a large section to avr_elf32_load_records_from_section() probably resulting in a crash or in some cases memory corruption. The highest threat from this vulnerability is to integrity as well as system availability.(CVE-2021-3549)
The _bfd_XX_bfd_copy_private_bfd_data_common function in peXXigen.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.30, processes a negative Data Directory size with an unbounded loop that increases the value of (external_IMAGE_DEBUG_DIRECTORY) *edd so that the address exceeds its own memory region, resulting in an out-of-bounds memory write, as demonstrated by objcopy copying private info with _bfd_pex64_bfd_copy_private_bfd_data_common in pex64igen.c.(CVE-2018-10534)
The ignore_section_sym function in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.30, does not validate the output_section pointer in the case of a symtab entry with a 'SECTION' type that has a '0' value, which allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a crafted file, as demonstrated by objcopy.(CVE-2018-10535)");

  script_tag(name:"affected", value:"'bindutils' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.27~28.base.1.h53.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
