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
  script_oid("1.3.6.1.4.1.25623.1.0.883363");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2019-20934", "CVE-2020-11668", "CVE-2021-33033", "CVE-2021-33034", "CVE-2021-33909");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-23 03:00:46 +0000 (Fri, 23 Jul 2021)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2021:2725)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:2725");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-July/048344.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2021:2725 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: size_t-to-int conversion vulnerability in the filesystem layer
(CVE-2021-33909)

  * kernel: use-after-free in net/bluetooth/hci_event.c when destroying an
hci_chan (CVE-2021-33034)

  * kernel: use-after-free in show_numa_stats function (CVE-2019-20934)

  * kernel: mishandles invalid descriptors in
drivers/media/usb/gspca/xirlink_cit.c (CVE-2020-11668)

  * kernel: use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c
(CVE-2021-33033)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * [RHEL7.9.z] n_tty_open: 'BUG: unable to handle kernel paging request'
(BZ#1872778)

  * [ESXi][RHEL7.8]'qp_alloc_hypercall result = -20' / 'Could not attach to
queue pair with -20' with vSphere Fault Tolerance enabled (BZ#1892237)

  * [RHEL7.9][s390x][Regression] Sino Nomine swapgen IBM z/VM emulated DASD
with DIAG driver returns EOPNOTSUPP (BZ#1910395)

  * False-positive hard lockup detected while processing the thread state
information (SysRq-T) (BZ#1912221)

  * RHEL7.9 zstream - s390x LPAR with NVMe SSD will panic when it has 32 or
more IFL (pci) (BZ#1917943)

  * The NMI watchdog detected a hard lockup while printing RCU CPU stall
warning messages to the serial console (BZ#1924688)

  * nvme hangs when trying to allocate reserved tag (BZ#1926825)

  * [REGRESSION] 'call into AER handling regardless of severity' triggers
do_recovery() unnecessarily on correctable PCIe errors (BZ#1933663)

  * Module nvme_core: A double free  of the kmalloc-512 cache between
nvme_trans_log_temperature() and nvme_get_log_page(). (BZ#1946793)

  * sctp - SCTP_CMD_TIMER_START queues active timer kernel BUG at
kernel/timer.c:1000! (BZ#1953052)

  * [Hyper-V][RHEL-7]When CONFIG_NET_POLL_CONTROLLER is set, mainline commit
2a7f8c3b1d3fee is needed (BZ#1953075)

  * Kernel panic at cgroup_is_descendant (BZ#1957719)

  * [Hyper-V][RHEL-7]Commits To Fix Kdump Failures (BZ#1957803)

  * IGMPv2 JOIN packets incorrectly routed to loopback (BZ#1958339)

  * [CKI kernel builds]: x86 binaries in non-x86 kernel rpms breaks systemtap
[7.9.z] (BZ#1960193)

  * mlx4: Fix memory allocation in mlx4_buddy_init needed (BZ#1962406)

  * incorrect assertion on pi_state->pi_mutex.wait_lock from
pi_state_update_owner() (BZ#1965495)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.36.2.el7", rls:"CentOS7"))) {
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