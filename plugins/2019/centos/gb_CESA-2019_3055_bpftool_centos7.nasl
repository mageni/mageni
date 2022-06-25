# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883117");
  script_version("2019-10-24T06:55:50+0000");
  script_cve_id("CVE-2018-20856", "CVE-2019-3846", "CVE-2019-9506", "CVE-2019-10126");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-24 06:55:50 +0000 (Thu, 24 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-22 02:01:55 +0000 (Tue, 22 Oct 2019)");
  script_name("CentOS Update for bpftool CESA-2019:3055 centos7 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-October/023488.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2019:3055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: Use-after-free in __blk_drain_queue() function in
block/blk-core.c (CVE-2018-20856)

  * kernel: Heap overflow in mwifiex_update_bss_desc_with_ie function in
marvell/mwifiex/scan.c (CVE-2019-3846)

  * hardware: bluetooth: BR/EDR encryption key negotiation attacks (KNOB)
(CVE-2019-9506)

  * kernel: Heap overflow in mwifiex_uap_parse_tail_ies function in
drivers/net/wireless/marvell/mwifiex/ie.c (CVE-2019-10126)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fixes:

  * gfs2: Fix iomap write page reclaim deadlock (BZ#1737373)

  * [FJ7.6 Bug]: [REG] kernel: ipc: ipc_free should use kvfree (BZ#1740178)

  * high update_cfs_rq_blocked_load contention (BZ#1740180)

  * [Hyper-V][RHEL 7] kdump fails to start on a Hyper-V guest of Windows
Server 2019. (BZ#1740188)

  * kvm: backport cpuidle-haltpoll driver (BZ#1740192)

  * Growing unreclaimable slab memory (BZ#1741920)

  * [bnx2x] ping failed from pf to vf which has been attached to vm
(BZ#1741926)

  * [Hyper-V]vPCI devices cannot allocate IRQs vectors in a Hyper-V VM with >
240 vCPUs (i.e., when in x2APIC mode) (BZ#1743324)

  * Macsec: inbound MACSEC frame is unexpectedly dropped with InPktsNotValid
(BZ#1744442)

  * RHEL 7.7 Beta - Hit error when trying to run nvme connect with IPv6
address (BZ#1744443)

  * RHEL 7.6 SS4 - Paths lost when running straight I/O on NVMe/RoCE system
(BZ#1744444)

  * NFSv4.0 client sending a double CLOSE (leading to EIO application
failure) (BZ#1744946)

  * [Azure] CRI-RDOS <pipe> [RHEL 7.8] Live migration only takes 10 seconds, but
the VM was unavailable for 2 hours (BZ#1748239)

  * NFS client autodisconnect timer may fire immediately after TCP connection
setup and may cause DoS type reconnect problem in complex network
environments (BZ#1749290)

  * [Inspur] RHEL7.6 ASPEED graphic card display issue (BZ#1749296)

  * Allows macvlan to operated correctly over the active-backup mode to
support bonding events. (BZ#1751579)

  * [LLNL 7.5 Bug] slab leak causing a crash when using kmem control group
(BZ#1752421)

Users of kernel are advised to upgrade to these updated packages, which fix
these bugs.");

  script_tag(name:"affected", value:"'bpftool' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1062.4.1.el7", rls:"CentOS7"))) {
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
