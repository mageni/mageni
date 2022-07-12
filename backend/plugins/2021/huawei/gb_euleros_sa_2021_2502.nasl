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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2502");
  script_cve_id("CVE-2020-14381", "CVE-2020-25673", "CVE-2020-28097", "CVE-2020-36385", "CVE-2020-36386", "CVE-2021-0129", "CVE-2021-28950", "CVE-2021-3347", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-35039", "CVE-2021-3564", "CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-09-28 07:08:10 +0000 (Tue, 28 Sep 2021)");
  script_version("2021-09-28T07:08:10+0000");
  script_tag(name:"last_modification", value:"2021-09-28 10:14:46 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:00:00 +0000 (Tue, 08 Dec 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-2502)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2502");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2502");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2021-2502 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The vgacon subsystem in the Linux kernel before 5.8.10 mishandles software scrollback. There is a vgacon_scrolldelta out-of-bounds read, aka CID-973c096f6a85.(CVE-2020-28097)

A flaw was found in the Linux kernel's futex implementation. This flaw allows a local attacker to corrupt system memory or escalate their privileges when creating a futex on a filesystem that is about to be unmounted. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.(CVE-2020-14381)

A flaw incorrect handle of boot param module.sig_enforce=1 in the Linux kernel modules sign verification functionality was found in the way user boot with this param enabled and both if kernel compiled with param CONFIG_MODULE_SIG unset, then user still can load unsigned module even param module.sig_enforce pretending to be enabled. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-35039)

An out-of-bounds write flaw was found in the Linux kernel's seq_file in the Filesystem layer. This flaw allows a local attacker with a user privilege to gain access to out-of-bound memory, leading to a system crash or a leak of internal kernel information. The issue results from not validating the size_t-to-int conversion prior to performing operations. The highest threat from this vulnerability is to data integrity, confidentiality and system availability.(CVE-2021-33909)

The canbus filesystem in the Linux kernel contains an information leak of kernel memory to devices on the CAN bus network link layer. An attacker with the ability to dump messages on the CAN bus is able to learn of uninitialized stack values by dumbing messages on the can bus(CVE-2021-34693)

A flaw out of bounds memory access in the Linux kernel bluetooth subsystem was found in the way when some data being read about the bluetooth device with the hci_extended_inquiry_result_evt call. A local user could use this flaw to crash the system or read some data out of memory bounds that can lead to data confidentiality threat.(CVE-2020-36386)

An issue was discovered in the Linux kernels Userspace Connection Manager Access for RDMA. This could allow a local attacker to crash the system, corrupt memory or escalate privileges.(CVE-2020-36385)

A flaw was found in the Linux kernel. A use-after-free memory flaw in the Fast Userspace Mutexes functionality allowing a local user to crash the system or escalate their privileges on the system. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-3347)

An issue was discovered in fs/fuse/fuse_i.h in the Linux kernel before 5.11.8. A 'stall on CPU' can occur because a retry loop continually finds the same bad inode, aka CID-775c5033a0d1.(CVE-2021-28950)

A vulnerability was found in Linux kernel where non-blocking socket in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.5.h615.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
