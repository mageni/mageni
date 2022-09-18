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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2318");
  script_cve_id("CVE-2021-3695", "CVE-2021-3696", "CVE-2021-3697", "CVE-2022-28733", "CVE-2022-28734", "CVE-2022-28736");
  script_tag(name:"creation_date", value:"2022-09-14 04:42:02 +0000 (Wed, 14 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 20:51:00 +0000 (Fri, 15 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2022-2318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2318");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2318");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2022-2318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability was found on grub2's chainloader command. This flaw allows an attacker to gain access to restricted data or cause arbitrary code execution if they can establish control from grub's memory allocation pattern.(CVE-2022-28736)

A flaw was found in grub2 when handling split HTTP headers. While processing a split HTTP header, grub2 wrongly advances its control pointer to the internal buffer by one position, which can lead to an out-of-bounds write. This flaw allows an attacker to leverage this issue by crafting a malicious set of HTTP packages making grub2 corrupt its internal memory metadata structure. This leads to data integrity and confidentiality issues or forces grub to crash, resulting in a denial of service attack.(CVE-2022-28734)

A flaw was found in grub2 when handling IPv4 packets. This flaw allows an attacker to craft a malicious packet, triggering an integer underflow in grub code. Consequently, the memory allocation for handling the packet data may be smaller than the size needed. This issue causes an out-of-bands write during packet handling, compromising data integrity, confidentiality issues, a denial of service, and remote code execution.(CVE-2022-28733)

A crafted JPEG image may lead the JPEG reader to underflow its data pointer, allowing user-controlled data to be written in heap. To a successful to be performed the attacker needs to perform some triage over the heap layout and craft an image with a malicious format and payload. This vulnerability can lead to data corruption and eventual code execution or secure boot circumvention. This flaw affects grub2 versions prior grub-2.12.(CVE-2021-3697)

A heap out-of-bounds write may heppen during the handling of Huffman tables in the PNG reader. This may lead to data corruption in the heap space. Confidentiality, Integrity and Availablity impact may be considered Low as it's very complex to an attacker control the encoding and positioning of corrupted Huffman entries to achieve results such as arbitrary code execution and/or secure boot circumvention. This flaw affects grub2 versions prior grub-2.12.(CVE-2021-3696)

A crafted 16-bit grayscale PNG image may lead to a out-of-bounds write in the heap area. An attacker may take advantage of that to cause heap data corruption or eventually arbitrary code execution and circumvent secure boot protections. This issue has a high complexity to be exploited as an attacker needs to perform some triage over the heap layout to achieve signifcant results, also the values written into the memory are repeated three times in a row making difficult to produce valid payloads. This flaw affects grub2 versions prior grub-2.12.(CVE-2021-3695)");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64", rpm:"grub2-efi-aa64~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-modules", rpm:"grub2-efi-aa64-modules~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.02~73.h39.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
