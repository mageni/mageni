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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1595.1");
  script_cve_id("CVE-2020-36310", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-28950", "CVE-2021-29155", "CVE-2021-29650", "CVE-2021-3444");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:29:59+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 19:20:00 +0000 (Thu, 22 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1595-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211595-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-36312: Fixed an issue within virt/kvm/kvm_main.c that had a
 kvm_io_bus_unregister_dev memory leak upon a kmalloc failure
 (bnc#1184509).

CVE-2021-29650: Fixed an issue within the netfilter subsystem that
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

CVE-2020-36310: Fixed an issue within arch/x86/kvm/svm/svm.c that
 allowed a set_memory_region_test infinite loop for certain nested page
 faults (bnc#1184512).

CVE-2021-28950: Fixed an issue within fs/fuse/fuse_i.h where a 'stall on
 CPU' could have occured because a retry loop continually finds the same
 bad inode (bnc#1184194, bnc#1184211).

CVE-2020-36322: Fixed an issue within the FUSE filesystem implementation
 where fuse_do_getattr() calls make_bad_inode() in inappropriate
 situations, causing a system crash. NOTE: the original fix for this
 vulnerability was incomplete, and its incompleteness is tracked as
 CVE-2021-28950 (bnc#1184211, bnc#1184952).

CVE-2021-3444: Fixed incorrect mod32 BPF verifier truncation
 (bsc#1184170).

The following non-security bugs were fixed:

arm64: PCI: mobiveil: remove driver Prepare to replace it with
 upstreamed driver

blk-settings: align max_sectors on 'logical_block_size' boundary
 (bsc#1185195).

block: fix use-after-free on cached last_lookup partition (bsc#1181062).

block: recalculate segment count for multi-segment discards correctly
 (bsc#1184724).

btrfs: fix qgroup data rsv leak caused by falloc failure (bsc#1185549).

btrfs: track qgroup released data in own variable in
 insert_prealloc_file_extent (bsc#1185549).

cdc-acm: fix BREAK rx code path adding necessary calls (git-fixes).

cxgb4: avoid collecting SGE_QBASE regs during traffic (bsc#1097585
 bsc#1097586 bsc#1097587 bsc#1097588 bsc#1097583 bsc#1097584).

drivers/perf: thunderx2_pmu: Fix memory resource error handling
 (git-fixes).

ext4: find old entry again if failed to rename whiteout (bsc#1184742).

ext4: fix potential error in ext4_do_update_inode (bsc#1184731).

fs: direct-io: fix missing sdio->boundary (bsc#1184736).

handle also the opposite type of race condition

i40e: Fix display statistics for veb_tc (bsc#1111981).

i40e: Fix kernel oops whe... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise High Availability 12-SP5");

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

if(release == "SLES12.0SP5") {
  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.71.1", rls:"SLES12.0SP5"))){
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
