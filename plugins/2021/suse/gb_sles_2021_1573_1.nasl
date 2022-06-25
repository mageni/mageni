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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1573.1");
  script_cve_id("CVE-2020-0433", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-27170", "CVE-2020-27171", "CVE-2020-27673", "CVE-2020-27815", "CVE-2020-35519", "CVE-2020-36310", "CVE-2020-36311", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-20219", "CVE-2021-26931", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29155", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-29650", "CVE-2021-30002", "CVE-2021-3428", "CVE-2021-3444", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:29:59+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-24 14:49:00 +0000 (Thu, 24 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1573-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211573-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a
 kvm_io_bus_unregister_dev memory leak upon a kmalloc failure
 (bnc#1184509).

CVE-2021-29650: Fixed an issue inside the netfilter subsystem that
 allowed attackers to cause a denial of service (panic) because
 net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h lack a
 full memory barrier upon the assignment of a new table value
 (bnc#1184208).

CVE-2021-29155: Fixed an issue within kernel/bpf/verifier.c that
 performed undesirable out-of-bounds speculation on pointer arithmetic,
 leading to side-channel attacks that defeat Spectre mitigations and
 obtain sensitive information from kernel memory. Specifically, for
 sequences of pointer arithmetic operations, the pointer modification
 performed by the first operation is not correctly accounted for when
 restricting subsequent operations (bnc#1184942).

CVE-2020-36310: Fixed an issue in arch/x86/kvm/svm/svm.c that allowed a
 set_memory_region_test infinite loop for certain nested page faults
 (bnc#1184512).

CVE-2020-27673: Fixed an issue in Xen where a guest OS users could have
 caused a denial of service (host OS hang) via a high rate of events to
 dom0 (bnc#1177411, bnc#1184583).

CVE-2021-29154: Fixed BPF JIT compilers that allowed to execute
 arbitrary code within the kernel context (bnc#1184391).

CVE-2020-25673: Fixed NFC endless loops caused by repeated
 llcp_sock_connect() (bsc#1178181).

CVE-2020-25672: Fixed NFC memory leak in llcp_sock_connect()
 (bsc#1178181).

CVE-2020-25671: Fixed NFC refcount leak in llcp_sock_connect()
 (bsc#1178181).

CVE-2020-25670: Fixed NFC refcount leak in llcp_sock_bind()
 (bsc#1178181).

CVE-2020-36311: Fixed an issue in arch/x86/kvm/svm/sev.c that allowed
 attackers to cause a denial of service (soft lockup) by triggering
 destruction of a large SEV VM (which requires unregistering many
 encrypted regions) (bnc#1184511).

CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h where a 'stall on
 CPU' could have occured because a retry loop continually finds the same
 bad inode (bnc#1184194, bnc#1184211).

CVE-2020-36322: Fixed an issue inside the FUSE filesystem implementation
 where fuse_do_getattr() calls make_bad_inode() in inappropriate
 situations, could have caused a system crash. NOTE: the original fix for
 this vulnerability was incomplete, and its incompleteness is tracked as
 CVE-2021-28950 (bnc#1184211).

CVE-2021-30002: Fixed a memory leak issue when a webcam device exists
 (bnc#1184120).

CVE-2021-3483: Fixed a use-after-free bug in nosy_ioctl() (bsc#1184393).

CVE-2021-20219: Fixed a denial of service vulnerability in
 drivers/tty/n_tty.c of the Linux kernel. In this flaw a local attacker
 with a normal user privilege could have delayed the loop and cause a
 threat to... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Availability 15");

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

if(release == "SLES15.0") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.72.2", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~150.72.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~150.72.1", rls:"SLES15.0"))){
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
