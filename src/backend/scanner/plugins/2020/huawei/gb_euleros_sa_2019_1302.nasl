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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1302");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2018-10876", "CVE-2018-10882", "CVE-2018-16862", "CVE-2018-19985", "CVE-2018-9568", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-5489", "CVE-2019-7221", "CVE-2019-9213");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:38:10 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1302");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's ext4 filesystem code. A use-after-free is possible in ext4_ext_remove_space() function when mounting and operating a crafted ext4 image.(CVE-2018-10876)

A flaw was found in the Linux kernel's ext4 filesystem. A local user can cause an out-of-bound write in the fs/jbd2/transaction.c code, a denial of service, and a system crash by unmounting a crafted ext4 filesystem image.(CVE-2018-10882)

A use-after-free vulnerability was found in the way the Linux kernel's KVM hypervisor emulates a preemption timer for L2 guests when nested (=1) virtualization is enabled. This high resolution timer(hrtimer) runs when a L2 guest is active. After VM exit, the sync_vmcs12() timer object is stopped. The use-after-free occurs if the timer object is freed before calling sync_vmcs12() routine. A guest user/process could use this flaw to crash the host kernel resulting in a denial of service or, potentially, gain privileged access to a system.(CVE-2019-7221)

A flaw was found in the Linux kernel in the function hso_probe() which reads if_num value from the USB device (as an u8) and uses it without a length check to index an array, resulting in an OOB memory read in hso_probe() or hso_get_config_data(). An attacker with a forged USB device and physical access to a system (needed to connect such a device) can cause a system crash and a denial of service.(CVE-2018-19985)

A possible memory corruption due to a type confusion was found in the Linux kernel in the sk_clone_lock() function in the net/core/sock.c. The possibility of local escalation of privileges cannot be fully ruled out for a local unprivileged attacker.(CVE-2018-9568)

A flaw was found in the Linux kernels implementation of Logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack. An attacker with physical access within the range of standard Bluetooth transmission can create a specially crafted packet. The response to this specially crafted packet can contain part of the kernel stack which can be used in a further attack.(CVE-2019-3459)

A flaw was found in the Linux kernel's implementation of logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack in the l2cap_parse_conf_rsp and l2cap_parse_conf_req functions. An attacker with physical access within the range of standard Bluetooth transmission can create a specially crafted packet. The response to this specially crafted packet can contain part of the kernel stack which can be used in a further attack.(CVE-2019-3460)

A flaw was found in mmap in the Linux kernel allowing the process to map a null page. This all ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.62.59.83.h149", rls:"EULEROS-2.0SP2"))) {
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