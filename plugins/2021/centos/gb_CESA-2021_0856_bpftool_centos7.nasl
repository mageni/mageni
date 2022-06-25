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
  script_oid("1.3.6.1.4.1.25623.1.0.883333");
  script_version("2021-03-30T03:35:09+0000");
  script_cve_id("CVE-2019-19532", "CVE-2020-0427", "CVE-2020-7053", "CVE-2020-14351", "CVE-2020-25211", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25705", "CVE-2020-28374", "CVE-2020-29661", "CVE-2021-20265");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-19 04:00:44 +0000 (Fri, 19 Mar 2021)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2021:0856)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:0856");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-March/048295.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2021:0856 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: Local buffer overflow in ctnetlink_parse_tuple_filter in
net/netfilter/nf_conntrack_netlink.c (CVE-2020-25211)

  * kernel: SCSI target (LIO) write to any block on ILO backstore
(CVE-2020-28374)

  * kernel: locking issue in drivers/tty/tty_jobctrl.c can lead to an
use-after-free (CVE-2020-29661)

  * kernel: malicious USB devices can lead to multiple out-of-bounds write
(CVE-2019-19532)

  * kernel: out-of-bounds reads in pinctrl subsystem. (CVE-2020-0427)

  * kernel: use-after-free in i915_ppgtt_close in
drivers/gpu/drm/i915/i915_gem_gtt.c (CVE-2020-7053)

  * kernel: performance counters race condition use-after-free
(CVE-2020-14351)

  * kernel: Geneve/IPsec traffic may be unencrypted between two Geneve
endpoints (CVE-2020-25645)

  * kernel: use-after-free in read in vt_do_kdgkb_ioctl (CVE-2020-25656)

  * kernel: ICMP rate limiting can be used for DNS poisoning attack
(CVE-2020-25705)

  * kernel: increase slab leak leads to DoS (CVE-2021-20265)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * BUG: scheduling while atomic: memory allocation under spinlock in
scsi_register_device_handler() (BZ#1619147)

  * WARNING in __iscsit_free_cmd during recovery Abort (BZ#1784540)

  * lpfc does not issue adisc to fcp-2 devices, does not respond to nvme
target that send an adisc. (BZ#1875961)

  * Panic in semctl_nolock.constprop.15+0x25b (BZ#1877264)

  * [RHEL 7.7][md]Crash due to invalid pool workqueue pointer, work queue
race (BZ#1889372)

  * Guest crash on intel CPU with -cpu host, -spec-ctrl, +ibpb (BZ#1890669)

  * RHEL7.9 - kernel/uv: handle length extension properly (BZ#1899172)

  * Commit b144f013fc16a06d7a4b9a4be668a3583fafeda2 'i40e: don't report link
up for a VF who hasn't enabled queues' introducing issues with VM using
DPDK (BZ#1901064)

  * writing to /sys/devices/(...)/net/eno49/queues/tx-16/xps_cpus triggers
kernel panic (BZ#1903819)

  * [Hyper-V][RHEL-7.9]video: hyperv_fb: Fix the cache type when mapping the
VRAM Edit (BZ#1908896)

  * kvm-rhel7.9 [AMD] - system crash observed while powering on virtual
machine with attached VF interfaces. (BZ#1909036)

  * kernel: nvme nvme7: Connect command failed, error wo/DNR bit: 2
(BZ#1910817)

  * dm-mirror crashes from assuming underlying storage will have a non-NULL
merge_bvec_fn (BZ#1916407)

  * watchdog: use nmi registers snapshot in hardlockup handler (BZ#1916589)

  * [DELL EMC 7.9 BUG] - Intel E810 NIC interfaces are not functional in RHEL
7.9 on system with AMD Rome CPUs (BZ#1918273)

  * [DELL EMC BUG] RHEL system log shows AMD-Vi error when system connected
with Gen 4 NVMe drives. (BZ#1921187)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.21.1.el7", rls:"CentOS7"))) {
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
