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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2082");
  script_cve_id("CVE-2020-14394", "CVE-2021-3507", "CVE-2021-3611", "CVE-2021-3750", "CVE-2021-4158", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-0216", "CVE-2022-0358", "CVE-2022-26353", "CVE-2022-26354", "CVE-2022-3165", "CVE-2022-35414", "CVE-2022-3872", "CVE-2022-4144", "CVE-2023-0330");
  script_tag(name:"creation_date", value:"2023-06-07 04:14:30 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-07T05:05:00+0000");
  script_tag(name:"last_modification", value:"2023-06-07 05:05:00 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-18 14:08:00 +0000 (Mon, 18 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2023-2082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2082");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2082");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2023-2082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A DMA reentrancy issue was found in the USB EHCI controller emulation of QEMU. EHCI does not verify if the Buffer Pointer overlaps with its MMIO region when it transfers the USB packets. Crafted content may be written to the controller's registers and trigger undesirable actions (such as reset) while the device is still transferring packets. This can ultimately lead to a use-after-free issue. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition, or potentially execute arbitrary code within the context of the QEMU process on the host. This flaw affects QEMU versions before 7.0.0.(CVE-2021-3750)

A flaw was found in the virtio-net device of QEMU. This flaw was inadvertently introduced with the fix for CVE-2021-3748, which forgot to unmap the cached virtqueue elements on error, leading to memory leakage and other unexpected results. Affected QEMU version: 6.2.0.(CVE-2022-26353)

A flaw was found in the QXL display device emulation in QEMU. An integer overflow in the cursor_alloc() function can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer overflow. This flaw allows a malicious privileged guest user to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU process.(CVE-2021-4206)

A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU process.(CVE-2021-4207)

A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results. Affected QEMU versions <= 6.2.0.(CVE-2022-26354)

A heap buffer overflow was found in the floppy disk emulator of QEMU up to 6.0.0 (including). It could occur in fdctrl_transfer_handler() in hw/block/fdc.c while processing DMA read data transfers from the floppy drive to the guest system. A privileged guest user could use this flaw to crash the QEMU process on the host resulting in DoS scenario, or potential information leakage from the host memory.(CVE-2021-3507)

** DISPUTED ** softmmu/physmem.c in QEMU through 7.0.0 can perform an uninitialized read on the translate_fail path, leading to an io_readx or io_writex crash. NOTE: a third party states that the Non-virtualization Use Case in the qemu.org reference applies here, i.e., 'Bugs affecting the non-virtualization use case are not considered security bugs at this time.'(CVE-2022-35414)

A use-after-free vulnerability was found in the LSI53C895A ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

if(release == "EULEROSVIRT-2.11.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~6.2.0~391", rls:"EULEROSVIRT-2.11.1"))) {
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
