# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1444");
  script_version("2020-01-23T14:09:13+0000");
  script_cve_id("CVE-2016-9602", "CVE-2017-13672", "CVE-2017-13673", "CVE-2017-14167", "CVE-2017-15119", "CVE-2017-15124", "CVE-2017-15268", "CVE-2017-18043", "CVE-2017-5579", "CVE-2017-8284", "CVE-2017-8379", "CVE-2017-9330", "CVE-2017-9373", "CVE-2018-10839", "CVE-2018-12617", "CVE-2018-7550");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 14:09:13 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:47:15 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2019-1444)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1444");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'qemu' package(s) announced via the EulerOS-SA-2019-1444 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow issue was found in the NE200 NIC emulation. It could occur while receiving packets from the network, if the size value was greater than INT_MAX. Such overflow would lead to stack buffer overflow issue. A user inside guest could use this flaw to crash the QEMU process, resulting in DoS scenario. (CVE-2018-10839)

qmp_guest_file_read in qga/commands-posix.c and qga/commands-win32.c in qemu-ga (aka QEMU Guest Agent) in QEMU 2.12.50 has an integer overflow causing a g_malloc0() call to trigger a segmentation fault when trying to allocate a large memory chunk. The vulnerability can be exploited by sending a crafted QMP command (including guest-file-read with a large count value) to the agent via the listening socket.(CVE-2018-12617)

Qemu before version 2.9 is vulnerable to an improper link following when built with the VirtFS. A privileged user inside guest could use this flaw to access host file system beyond the shared folder and potentially escalating their privileges on a host. (CVE-2016-9602)

Quick Emulator (QEMU), compiled with the PC System Emulator with multiboot feature support, is vulnerable to an OOB r/w memory access issue. The issue could occur while loading a kernel image during the guest boot, if mh_load_end_addr address is greater than the mh_bss_end_addr address. A user or process could use this flaw to potentially achieve arbitrary code execution on a host.(CVE-2018-7550)

An out-of-bounds read access issue was found in the VGA display emulator built into the Quick emulator (QEMU). It could occur while reading VGA memory to update graphics display. A privileged user/process inside guest could use this flaw to crash the QEMU process on the host resulting in denial of service situation.(CVE-2017-13672)

An assert failure issue was found in the VGA display emulator built into the Quick emulator (QEMU). It could occur while updating graphics display, due to miscalculating region for dirty bitmap snapshot in split screen mode. A privileged user/process inside guest could use this flaw to crash the QEMU process on the host resulting in denial of service. (CVE-2017-13673)

The Network Block Device (NBD) server in Quick Emulator (QEMU), is vulnerable to a denial of service issue. It could occur if a client sent large option requests, making the server waste CPU time on reading up to 4GB per request. A client could use this flaw to keep the NBD server from serving other requests, resulting in DoS.(CVE-2017-15119)

QEMU (aka Quick Emulator) before 2.9.0, when built with the USB OHCI Emulation support, allows local guest OS users to cause a denial of service ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~2.8.1~30.027", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
