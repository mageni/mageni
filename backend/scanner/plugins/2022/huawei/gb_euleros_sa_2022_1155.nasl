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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1155");
  script_cve_id("CVE-2020-36385", "CVE-2020-36386", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-3347", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-35039", "CVE-2021-3609", "CVE-2021-3679", "CVE-2021-3753", "CVE-2021-38160", "CVE-2021-40490", "CVE-2021-42008");
  script_tag(name:"creation_date", value:"2022-02-13 03:23:50 +0000 (Sun, 13 Feb 2022)");
  script_version("2022-02-13T03:23:50+0000");
  script_tag(name:"last_modification", value:"2022-02-15 11:09:28 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-1155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1155");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1155");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-1155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw use-after-free in the Linux kernel CIPSO network packet labeling protocol functionality was found in the way user open local network connection with the usage of the security labeling that is IP option number 134. A local user could use this flaw to crash the system or possibly escalate their privileges on the system.(CVE-2021-33033)

An issue was discovered in the Linux kernels Userspace Connection Manager Access for RDMA. This could allow a local attacker to crash the system, corrupt memory or escalate privileges.(CVE-2020-36385)

A flaw out of bounds memory access in the Linux kernel bluetooth subsystem was found in the way when some data being read about the bluetooth device with the hci_extended_inquiry_result_evt call. A local user could use this flaw to crash the system or read some data out of memory bounds that can lead to data confidentiality threat.(CVE-2020-36386)

The canbus filesystem in the Linux kernel contains an information leak of kernel memory to devices on the CAN bus network link layer. An attacker with the ability to dump messages on the CAN bus is able to learn of uninitialized stack values by dumbing messages on the can bus.(CVE-2021-34693)

A flaw was found in the CAN BCM networking protocol in the Linux kernel, where a local attacker can abuse a flaw in the CAN subsystem to corrupt memory, crash the system or escalate privileges.(CVE-2021-3609)

An out-of-bounds write flaw was found in the Linux kernel's seq_file in the Filesystem layer. This flaw allows a local attacker with a user privilege to gain access to out-of-bound memory, leading to a system crash or a leak of internal kernel information. The issue results from not validating the size_t-to-int conversion prior to performing operations. The highest threat from this vulnerability is to data integrity, confidentiality and system availability.(CVE-2021-33909)

A flaw incorrect handle of boot param module.sig_enforce=1 in the Linux kernel modules sign verification functionality was found in the way user boot with this param enabled and both if kernel compiled with param CONFIG_MODULE_SIG unset, then user still can load unsigned module even param module.sig_enforce pretending to be enabled. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-35039)

A flaw was found in the Linux kernel. A race condition was discovered in the ext4 subsystem. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-40490)

The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.(CVE-2021-42008)

A lack of CPU resources in the Linux kernel tracing module functionality was found in the way users use the trace ring ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_152", rls:"EULEROSVIRT-3.0.6.6"))) {
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
