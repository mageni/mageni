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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1967");
  script_version("2021-06-07T09:15:08+0000");
  script_cve_id("CVE-2020-27170", "CVE-2020-27171", "CVE-2020-35519", "CVE-2020-36322", "CVE-2021-20292", "CVE-2021-23133", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28964", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-3483");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-08 10:08:36 +0000 (Tue, 08 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-07 09:15:08 +0000 (Mon, 07 Jun 2021)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1967)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1967");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1967");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2021-1967 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a flaw reported in drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue results from the lack of validating the existence of an object prior to performing operations on the object. An attacker with a local account with a root privilege, can leverage this vulnerability to escalate privileges and execute code in the context of the kernel.(CVE-2021-20292)

A flaw memory leak in the Linux kernel webcam device functionality was found in the way user calls ioctl that triggers video_usercopy function. The highest threat from this vulnerability is to system availability.(CVE-2021-30002)

A flaw was found in the Linux kernel. The usbip driver allows attackers to cause a denial of service (GPF) because the stub-up sequence has race conditions during an update of the local and shared status. The highest threat from this vulnerability is to system availability.(CVE-2021-29265)

A flaw in the Linux kernels implementation of the RPA PCI Hotplug driver for power-pc. A user with permissions to write to the sysfs settings for this driver can trigger a buffer overflow when writing a new device name to the driver from userspace, overwriting data in the kernel's stack.(CVE-2021-28972)

rtw_wx_set_scan in drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the Linux kernel through 5.11.6 allows writing beyond the end of the -ssid[] array. NOTE: from the perspective of kernel.org releases, CVE IDs are not normally used for drivers/staging/* (unfinished work), however, system integrators may have situations in which a drivers/staging issue is relevant to their own customer base.(CVE-2021-28660)

A race condition flaw was found in get_old_root in fs/btrfs/ctree.c in the Linux kernel in btrfs file-system. This flaw allows a local attacker with a special user privilege to cause a denial of service due to not locking an extent buffer before a cloning operation. The highest threat from this vulnerability is to system availability.(CVE-2021-28964)

A flaw was found in the Linux kernel. This flaw allows attackers to obtain sensitive information from kernel memory because of a partially uninitialized data structure. The highest threat from this vulnerability is to confidentiality.(CVE-2021-29647)

A flaw was found in the Linux kernel. The Freescale Gianfar Ethernet driver allows attackers to cause a system crash due to a negative fragment size calculated in situations involving an RX queue overrun when jumbo packets are used and NAPI is enabled. The highest threat from this vulnerability is to data integrity and system availability.(CVE-2021-2 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h462.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h462.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h462.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.90~vhulk2103.1.0.h462.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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