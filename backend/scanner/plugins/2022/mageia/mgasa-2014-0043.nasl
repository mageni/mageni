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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0043");
  script_cve_id("CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6382", "CVE-2014-0038", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1690");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-16 04:39:00 +0000 (Sun, 16 Mar 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0043");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0043.html");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.25");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.26");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.27");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.10.28");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12518");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2014-0043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update provides an update to the 3.10 longterm branch,
currently 3.10.28 and fixes the following security issues:

The ath9k_htc_set_bssid_mask function in
drivers/net/wireless/ath/ath9k/htc_drv_main.c in the Linux kernel through
3.12 uses a BSSID masking approach to determine the set of MAC addresses
on which a Wi-Fi device is listening, which allows remote attackers to
discover the original MAC address after spoofing by sending a series of
packets to MAC addresses with certain bit manipulations. (CVE-2013-4579)

Array index error in the kvm_vm_ioctl_create_vcpu function in
virt/kvm/kvm_main.c in the KVM subsystem in the Linux kernel through
3.12.5 allows local users to gain privileges via a large id value
(CVE-2013-4587)

The apic_get_tmcct function in arch/x86/kvm/lapic.c in the KVM subsystem
in the Linux kernel through 3.12.5 allows guest OS users to cause a denial
of service (divide-by-zero error and host OS crash) via crafted
modifications of the TMICT value. (CVE-2013-6367)

The KVM subsystem in the Linux kernel through 3.12.5 allows local users to
gain privileges or cause a denial of service (system crash) via a VAPIC
synchronization operation involving a page-end address. (CVE-2013-6368)

The recalculate_apic_map function in arch/x86/kvm/lapic.c in the KVM
subsystem in the Linux kernel through 3.12.5 allows guest OS users to
cause a denial of service (host OS crash) via a crafted ICR write
operation in x2apic mode. (CVE-2013-6376)

Multiple buffer underflows in the XFS implementation in the Linux kernel
through 3.12.1 allow local users to cause a denial of service (memory
corruption) or possibly have unspecified other impact by leveraging the
CAP_SYS_ADMIN capability for a (1) XFS_IOC_ATTRLIST_BY_HANDLE or (2)
XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted length value,
related to the xfs_attrlist_by_handle function in fs/xfs/xfs_ioctl.c
and the xfs_compat_attrlist_by_handle function in fs/xfs/xfs_ioctl32.c.
(CVE-2013-6382)

Pageexec reported a bug in the Linux kernel's recvmmsg syscall when called
from code using the x32 ABI. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash) or gain administrator
privileges (CVE-2014-0038)

Faults during task-switch due to unhandled FPU-exceptions allow to
kill processes at random on all affected kernels, resulting in local
DOS in the end. One some architectures, privilege escalation under
non-common circumstances is possible. (CVE-2014-1438)

The hamradio yam_ioctl() code fails to initialise the cmd field of the
struct yamdrv_ioctl_cfg leading to a 4-byte info leak. (CVE-2014-1446)

Linux kernel built with the NetFilter Connection Tracking(NF_CONNTRACK)
support for IRC protocol(NF_NAT_IRC), is vulnerable to an information
leakage flaw. It could occur when communicating over direct
client-to-client IRC connection(/dcc) via a NAT-ed network. Kernel
attempts to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-3.10.28-1.mga3", rpm:"kernel-linus-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-3.10.28-1.mga3", rpm:"kernel-linus-devel-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-3.10.28-1.mga3", rpm:"kernel-linus-source-3.10.28-1.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~3.10.28~1.mga3", rls:"MAGEIA3"))) {
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
