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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2654");
  script_cve_id("CVE-2021-33655", "CVE-2022-20153", "CVE-2022-20368", "CVE-2022-20369", "CVE-2022-2327", "CVE-2022-2380", "CVE-2022-2503", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-2639", "CVE-2022-2873", "CVE-2022-2964", "CVE-2022-36123", "CVE-2022-36879", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-11-03 04:26:17 +0000 (Thu, 03 Nov 2022)");
  script_version("2022-11-03T10:20:15+0000");
  script_tag(name:"last_modification", value:"2022-11-03 10:20:15 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-08 13:50:00 +0000 (Mon, 08 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-2654)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2654");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2654");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-2654 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.(CVE-2022-2964)

An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input data. This flaw allows a local user to crash the system.(CVE-2022-2873)

Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for peripherals that do not verify firmware updates. We recommend upgrading past commit 4caae58406f8ceb741603eee460d79bacca9b1b5(CVE-2022-2503)

The Linux kernel was found vulnerable out of bounds memory access in the drivers/video/fbdev/sm712fb.c:smtcfb_read() function. The vulnerability could result in local attackers being able to crash the kernel.(CVE-2022-2380)

When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of bounds.(CVE-2021-33655)

A use-after-free flaw was found in nf_tables cross-table in the net/netfilter/nf_tables_api.c function in the Linux kernel. This flaw allows a local, privileged attacker to cause a use-after-free problem at the time of table deletion, possibly leading to local privilege escalation.(CVE-2022-2586)

In rcu_cblist_dequeue of rcu_segcblist.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.(CVE-2022-20153)

io_uring use work_flags to determine which identity need to grab from the calling process to make sure it is consistent with the calling process when executing IORING_OP. Some operations are missing some types, which can lead to incorrect reference counts which can then lead to a double free. We recommend upgrading the kernel past commit df3f3bb5059d20ef094d6b2f0256c4bf4127a859(CVE-2022-2327)

An out-of-bounds access issue was found in the Linux kernel networking subsystem in the way raw packet sockets (AF_PACKET) used PACKET_COPY_THRESH and mmap operations. A local attacker with CAP_NET_RAW capability could use this flaw to trigger a buffer overflow resulting in a system crash or privilege escalation.(CVE-2022-20368)

A use-after-free flaw was found in route4_change in the net/sched/cls_route.c filter implementation in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2207.2.0.h1231.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2207.2.0.h1231.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2207.2.0.h1231.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2207.2.0.h1231.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2207.2.0.h1231.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
