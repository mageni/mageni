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
  script_oid("1.3.6.1.4.1.25623.1.0.883139");
  script_version("2019-12-06T11:38:15+0000");
  script_cve_id("CVE-2019-14821", "CVE-2019-15239");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-06 11:38:15 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-04 03:01:25 +0000 (Wed, 04 Dec 2019)");
  script_name("CentOS Update for bpftool CESA-2019:3979 centos7 ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-December/023536.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2019:3979 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Kernel: KVM: OOB memory access via mmio ring buffer (CVE-2019-14821)

  * kernel: local attacker can trigger multiple use-after-free conditions
results in privilege escalation (CVE-2019-15239)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * On RHEL 7.7 kernel SCSI VPD information for NVMe drives is missing
(breaks InfoScale) (BZ#1752423)

  * RHEL7 fnic spamming logs: Current vnic speed set to : 40000 (BZ#1754836)

  * kernel build: parallelize redhat/mod-sign.sh (BZ#1755330)

  * kernel build: speed up module compression step (BZ#1755339)

  * Nested VirtualBox VMs on Windows guest has the potential of impacting
memory region allocated to other KVM guests (BZ#1755781)

  * NULL pointer dereference at check_preempt_wakeup+0x109 (BZ#1756265)

  * Regression: panic in pick_next_task_rt (BZ#1756267)

  * ixgbe reports 'Detected Tx Unit Hang' with adapter reset on RHEL 7
(BZ#1757350)

  * [Intel 7.8 Bug] [KVM][CLX] CPUID_7_0_EDX_ARCH_CAPABILITIES is not enabled
in VM. (BZ#1757757)

  * nvme: dead loop in blk_mq_tagset_wait_completed_request() when it is
called from timeout handler (BZ#1758051)

  * [mlx5] VF Representer naming is not consistent/persistent through reboots
with OSPD deployment (BZ#1759003)

  * OS getting restarted because of driver issue with QLogic Corp.
ISP2532-based 8Gb Fibre Channel to PCI Express HBA [1077:2532] (rev 02).
(BZ#1759447)

  * mlx5: Load balancing not working over VF LAG configuration (BZ#1759449)

  * RHEL7.8 - ISST-LTE: vimlp1: Running LTP af_alg04.c (crypto) crash the
LPAR (BZ#1763620)

  * RHEL7.5 - Fix security issues on crypto vmx (BZ#1763621)

  * RHEL 7.7 RC1 - Host crashes about 4.5 hours into switch port bounce test
(BZ#1763624)

  * RHEL7.6 - cacheinfo code unsafe vs LPM (BZ#1763625)

  * xfs hangs on acquiring  xfs_buf semaphore (BZ#1764245)

  * single CPU VM hangs during open_posix_testsuite (BZ#1766087)

  * rcu_sched self-detected stall on CPU while booting with nohz_full
(BZ#1766098)");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1062.7.1.el7", rls:"CentOS7"))) {
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