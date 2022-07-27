# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2125");
  script_version("2021-07-07T09:11:54+0000");
  script_cve_id("CVE-2020-17380", "CVE-2020-25084", "CVE-2020-25085", "CVE-2020-25625", "CVE-2020-27617", "CVE-2020-28916", "CVE-2021-3409", "CVE-2021-3416");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-07-07 09:11:54 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-07 08:42:18 +0000 (Wed, 07 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2021-2125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2125");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2125");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'qemu-kvm' package(s) announced via the EulerOS-SA-2021-2125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in QEMU. A heap-based buffer overflow vulnerability was found in the SDHCI device emulation support allowing a guest user or process to crash the QEMU process on the host resulting in a denial of service condition, or potentially execute arbitrary code with privileges of the QEMU process on the host. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.CVE-2020-17380

A flaw was found in QEMU. An out-of-bounds read/write access issue was found in the SDHCI Controller emulator of QEMU. It may occur while doing multi block SDMA, if transfer block size exceeds the 's-fifo_buffer[s-buf_maxsz]' size which would leave the current element pointer 's-data_count' pointing out of bounds. This would lead the subsequent DMA r/w operation to an OOB access issue where a guest user/process may use this flaw to crash the QEMU process resulting in DoS scenario. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.CVE-2020-25085

The patch for CVE-2020-17380 and CVE-2020-25085, both involving a heap buffer overflow in the SDHCI controller emulation code of QEMU, was found to be incomplete. A malicious privileged guest could reproduce the same issues with specially crafted input, inducing a bogus transfer and subsequent out-of-bounds read/write access in sdhci_do_adma() or sdhci_sdma_transfer_multi_blocks(). CVE-2021-3409 was assigned to facilitate the tracking and backporting of the new patch.CVE-2021-3409

A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the host resulting in DoS scenario.(CVE-2021-3416)

An infinite loop flaw was found in the USB OHCI controller emulator of QEMU. This flaw occurs while servicing OHCI isochronous transfer descriptors (TD) in the ohci_service_iso_td routine, as it retires a TD if it has passed its time frame. It does not check if the TD was already processed and holds an error code in TD_CC. This issue may happen if the TD list has a loop. This flaw allows a guest user or process to consume CPU cycles on the host, resulting in a denial of service.(CVE-2020-25625)

An infinite loop flaw was found in the e1000e device emulator in QEMU. This issue could occur while receiving packets via the e1000e_write_packet_to_guest() routine, if the receive(RX) descriptor has a NULL buffer address. This fla ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.137", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.137", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.137", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.137", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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