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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2504");
  script_cve_id("CVE-2021-3695", "CVE-2021-3696", "CVE-2021-3981", "CVE-2022-28734");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 20:51:00 +0000 (Fri, 15 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2022-2504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2504");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2504");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2022-2504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in grub 2, where a crafted 16-bit grayscale PNG image may lead to an out-of-bounds write. This flaw allows an attacker to corrupt the data on the heap portion of the grub2's memory, leading to possible code execution and the circumvention of the secure boot mechanism.(CVE-2021-3695)

A flaw was found in grub2 when handling a PNG image header. When decoding the data contained in the Huffman table at the PNG file header, an out-of-bounds write may happen on grub's heap.(CVE-2021-3696)

A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong permission set allowing non privileged users to read its content. This represents a low severity confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg. This flaw affects grub2 2.06 and previous versions. This issue has been fixed in grub upstream but no version with the fix is currently released.(CVE-2021-3981)

A flaw was found in grub2 when handling split HTTP headers. While processing a split HTTP header, grub2 wrongly advances its control pointer to the internal buffer by one position, which can lead to an out-of-bounds write. This flaw allows an attacker to leverage this issue by crafting a malicious set of HTTP packages making grub2 corrupt its internal memory metadata structure. This leads to data integrity and confidentiality issues or forces grub to crash, resulting in a denial of service attack.(CVE-2022-28734)");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-ia32", rpm:"grub2-efi-ia32~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-ia32-cdboot", rpm:"grub2-efi-ia32-cdboot~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-cdboot", rpm:"grub2-efi-x64-cdboot~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.02~0.65.2.h25.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
