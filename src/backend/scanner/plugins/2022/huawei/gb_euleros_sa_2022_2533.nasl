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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2533");
  script_cve_id("CVE-2019-12067", "CVE-2021-20196", "CVE-2021-20255", "CVE-2021-20257", "CVE-2021-3748", "CVE-2021-3750", "CVE-2021-3930");
  script_tag(name:"creation_date", value:"2022-10-10 07:55:28 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 18:58:00 +0000 (Tue, 29 Mar 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-2533)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2533");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2533");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-2533 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.(CVE-2021-3930)

A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the descriptor's address belongs to the non direct access region, due to num_buffers being set after the virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a denial of service condition, or potentially execute code on the host with the privileges of the QEMU process.(CVE-2021-3748)

A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be written to the controller's registers and trigger undesirable actions (such as reset) while the device is still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of s(CVE-2021-3750)

A NULL pointer dereference flaw was found in the floppy disk emulator of QEMU. This issue occurs while processing read/write ioport commands if the selected floppy drive is not initialized with a block device. This flaw allows a privileged guest user to crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2021-20196)

A stack overflow via an infinite recursion vulnerability was found in the eepro100 i8255x device emulator of QEMU. This issue occurs while processing controller commands due to a DMA reentry issue. This flaw allows a guest user or process to consume CPU cycles or crash the QEMU process on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2021-20255)

The ahci_commit_buf function in ide/ahci.c in QEMU allows attackers to cause a denial of service (NULL dereference) when the command header 'ad->cur_cmd' is null.(CVE-2019-12067)

An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2021-20257)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~2.8.1~30.227", rls:"EULEROSVIRT-3.0.6.6"))) {
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
