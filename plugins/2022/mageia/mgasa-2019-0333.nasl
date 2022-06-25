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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0333");
  script_cve_id("CVE-2018-12207", "CVE-2019-0155", "CVE-2019-10207", "CVE-2019-11135", "CVE-2019-1125", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-16714", "CVE-2019-17666");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:22:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0333.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25687");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25688");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.2");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.3.11");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2019-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on the upstream 5.3.11 and fixes at least
the following security issues:

Insufficient access control in a subsystem for Intel (R) processor graphics
may allow an authenticated user to potentially enable escalation of
privilege via local access (CVE-2019-0155).

A Spectre SWAPGS gadget was found in the Linux kernel's implementation of
system interrupts. An attacker with local access could use this information
to reveal private data through a Spectre like side channel (CVE-2019-1125).

A flaw was found in the Linux kernel's Bluetooth implementation of UART.
An attacker with local access and write permissions to the Bluetooth
hardware could use this flaw to issue a specially crafted ioctl function
call and cause the system to crash (CVE-2019-10207).

TSX Asynchronous Abort condition on some CPUs utilizing speculative
execution may allow an authenticated user to potentially enable
information disclosure via a side channel with local access
(CVE-2019-11135).

Improper invalidation for page table updates by a virtual guest operating
system for multiple Intel(R) Processors may allow an authenticated user to
potentially enable denial of service of the host system via local access
(CVE-2018-12207).

For proper mitigations and fixes for these issues, a microcode update is
also needed, either with a bios/uefi update from your hardware vendor or
by installing the microcode-0.20191112-1.mga7.nonfree update (mga#25688).

There is heap-based buffer overflow in the marvell wifi chip driver that
allows local users to cause a denial of service(system crash) or possibly
execute arbitrary code (CVE-2019-14814, CVE-2019-14815, CVE-2019-14816).

An out-of-bounds access issue was found in the way Linux kernel's KVM
hypervisor implements the Coalesced MMIO write operation. It operates on
an MMIO ring buffer 'struct kvm_coalesced_mmio' object, wherein write
indices 'ring->first' and 'ring->last' value could be supplied by a host
user-space process. An unprivileged host user or process with access to
'/dev/kvm' device could use this flaw to crash the host kernel, resulting
in a denial of service or potentially escalating privileges on the system
(CVE-2019-14821).

A buffer overflow flaw was found in the way Linux kernel's vhost
functionality that translates virtqueue buffers to IOVs, logged the buffer
descriptors during migration. A privileged guest user able to pass
descriptors with invalid length to the host when migration is underway,
could use this flaw to increase their privileges on the host
(CVE-2019-14835).

In the Linux kernel before 5.2.14, rds6_inc_info_copy in net/rds/recv.c
allows attackers to obtain sensitive information from kernel stack memory
because tos and flags fields are not initialized (CVE-2019-16714)

rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux
kernel through 5.3.6 lacks a certain upper-bound check, leading to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.3.11-1.mga7", rpm:"kernel-linus-5.3.11-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.3.11-1.mga7", rpm:"kernel-linus-devel-5.3.11-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.3.11~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.3.11-1.mga7", rpm:"kernel-linus-source-5.3.11-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.3.11~1.mga7", rls:"MAGEIA7"))) {
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
