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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2071");
  script_cve_id("CVE-2019-20808", "CVE-2021-20257", "CVE-2021-3582", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3748", "CVE-2021-3930", "CVE-2021-4145", "CVE-2022-26354");
  script_tag(name:"creation_date", value:"2022-07-14 09:59:54 +0000 (Thu, 14 Jul 2022)");
  script_version("2022-07-14T09:59:54+0000");
  script_tag(name:"last_modification", value:"2022-07-14 09:59:54 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 18:58:00 +0000 (Tue, 29 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-2071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2071");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2071");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-2071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds read flaw was found in the ATI VGA implementation of the QEMU emulator. This flaw occurs in the ati_cursor_define() routine while handling MMIO write operations through ati_mm_write() callback. A malicious guest could abuse this flaw to crash the QEMU process, resulting in a denial of service.(CVE-2019-20808)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the bootp_input() function and could occur while processing a udp packet that is smaller than the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of uninitialized heap memory from the host. The highest threat from this vulnerability is to data confidentiality.(CVE-2021-3592)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality.(CVE-2021-3593)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp_input() function and could occur while processing a udp packet that is smaller than the size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality.(CVE-2021-3594)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality.(CVE-2021-3595)

An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.(CVE-2021-3930)

An integer overflow was found in the QEMU implementation of VMWare's paravirtual RDMA device. The issue occurs while handling a 'PVRDMA_REG_DSRHIGH' write from the guest due to improper input validation. This flaw allows a privileged guest user to make QEMU allocate a large amount of memory, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2021-3607)

A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. The issue occurs while handling a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.1.0~2.10.0.5.468", rls:"EULEROSVIRT-2.10.1"))) {
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
