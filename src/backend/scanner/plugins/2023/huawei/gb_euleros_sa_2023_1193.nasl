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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1193");
  script_cve_id("CVE-2021-33655", "CVE-2022-1462", "CVE-2022-20368", "CVE-2022-2503", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-2639", "CVE-2022-2663", "CVE-2022-2964", "CVE-2022-2977", "CVE-2022-3028", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39189");
  script_tag(name:"creation_date", value:"2023-01-12 04:15:41 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 18:37:00 +0000 (Thu, 08 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-1193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1193");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1193");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-1193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale TLB entries. This only occurs in situations with VM_PFNMAP VMAs.(CVE-2022-39188)

An issue was discovered the x86 KVM subsystem in the Linux kernel before 5.18.17. Unprivileged guest users can compromise the guest kernel because TLB flush operations are mishandled in certain KVM_VCPU_PREEMPTED situations.(CVE-2022-39189)

An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read unauthorized random data from memory.(CVE-2022-1462)

An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted IRC with nf_conntrack_irc configured.(CVE-2022-2663)

Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.(CVE-2022-26373)

A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-free and create a situation where it may be possible to escalate privileges on the system.(CVE-2022-2977)

A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.(CVE-2022-2964)

A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem) when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read and copying it into a socket.(CVE-2022-3028)

Dm-verity is used for extending root-of-trust to root filesystems. LoadPin builds on this property to restrict module/firmware loads to just the trusted root filesystem. Device-mapper table reloads currently allow users with root privileges to switch out the target with an equivalent dm-linear target and bypass verification till reboot. This allows root to bypass LoadPin and can be used to load untrusted and unverified kernel modules and firmware, which implies arbitrary kernel execution and persistence for peripherals that do not verify firmware updates. We recommend upgrading past commit ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h848.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h848.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h848.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h848.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
