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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1223");
  script_cve_id("CVE-2021-33061", "CVE-2021-39634", "CVE-2022-0812", "CVE-2022-1462", "CVE-2022-1679", "CVE-2022-20008", "CVE-2022-20368", "CVE-2022-2503", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-2873", "CVE-2022-2938", "CVE-2022-2964", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-3239", "CVE-2022-36123", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39189");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 18:37:00 +0000 (Thu, 08 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-1223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1223");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1223");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-1223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In mmc_blk_read_single of block.c, there is a possible way to read kernel heap memory due to uninitialized data. This could lead to local information disclosure if reading from an SD card that triggers errors, with no additional execution privileges needed. User interaction is not needed for exploitation.(CVE-2022-20008)

Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an authenticated user to potentially enable denial of service via local access.(CVE-2021-33061)

In fs/eventpoll.c, there is a possible use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.(CVE-2021-39634)

An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.(CVE-2022-0812)

A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local user to crash or potentially escalate their privileges on the system.(CVE-2022-1679)

An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED situations.(CVE-2022-39189)

A flaw use after free in the Linux kernel video4linux driver was found in the way user triggers em28xx_usb_probe() for the Empia 28xx based TV cards. A local user could use this flaw to crash the system or potentially escalate their privileges on the system.(CVE-2022-3239)

nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte nfta_payload attribute, an skb_pull can encounter a negative skb->len.(CVE-2022-36946)

The Linux kernel before 5.18.13 lacks a certain clear operation for the block starting symbol (.bss). This allows Xen PV guest OS users to cause a denial of service or gain privileges.(CVE-2022-36123)

An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read unauthorized random data from memory.(CVE-2022-1462)

A flaw was found in the Linux kernel's implementation of Pressure Stall Information. While the feature is disabled by default, it could allow an attacker to crash the system or have other memory-corruption side effects.(CVE-2022-2938)

An issue was discovered in include/asm-generic/tlb.h in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h841.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h841.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h841.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h841.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
