# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4346.1");
  script_cve_id("CVE-2023-31085", "CVE-2023-34324", "CVE-2023-39189", "CVE-2023-45862");
  script_tag(name:"creation_date", value:"2023-11-03 04:20:59 +0000 (Fri, 03 Nov 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-11 19:47:17 +0000 (Wed, 11 Oct 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4346-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234346-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-31085: Fixed a divide-by-zero error in do_div(sz,mtd->erasesize) that could cause a local DoS. (bsc#1210778)
CVE-2023-45862: Fixed an issue in the ENE UB6250 reader driver whwere an object could potentially extend beyond the end of an allocation causing. (bsc#1216051)
CVE-2023-34324: Fixed a possible deadlock in Linux kernel event handling. (bsc#1215745).
CVE-2023-39189: Fixed a flaw in the Netfilter subsystem that could allow a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure. (bsc#1216046)

The following non-security bugs were fixed:

9p: virtio: make sure 'offs' is initialized in zc_request (git-fixes).
audit: fix potential double free on error path from fsnotify_add_inode_mark (git-fixes).
crypto: virtio: Fix use-after-free in virtio_crypto_skcipher_finalize_req() (git-fixes).
iommu/amd: Fix IOMMU interrupt generation in X2APIC mode (bsc#1206010).
iommu/amd: Remove useless irq affinity notifier (bsc#1206010).
iommu/amd: Set iommu->int_enabled consistently when interrupts are set up (bsc#1206010).
kabi: iommu/amd: Fix IOMMU interrupt generation in X2APIC mode (bsc#1206010).
KVM: s390: fix sthyi error handling (git-fixes bsc#1216107).
memcg: drop kmem.limit_in_bytes (bsc#1208788) This brings a breaking commit for easier backport, it'll be fixed differently in a following commit.
mm, memcg: reconsider kmem.limit_in_bytes deprecation (bsc#1208788 bsc#1213705).
net: usb: dm9601: fix uninitialized variable use in dm9601_mdio_read (git-fixes).
net: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg (git-fixes).
ratelimit: Fix data-races in ___ratelimit() (git-fixes).
ring-buffer: Fix bytes info in per_cpu buffer stats (git-fixes).
s390/pci: fix iommu bitmap allocation (git-fixes bsc#1216513).
s390/ptrace: fix setting syscall number (git-fixes bsc#1216340).
s390/vdso: add missing FORCE to build targets (git-fixes bsc#1216140).
s390/zcrypt: change reply buffer size offering (LTC#203322 bsc#1213950).
s390/zcrypt: fix reply buffer calculations for CCA replies (LTC#203322 bsc#1213950).
sched: Avoid scale real weight down to zero (git fixes (sched)).
sched: correct SD_flags returned by tl->sd_flags() (git fixes (sched)).
sched: Reenable interrupts in do_sched_yield() (git fixes (sched)).
sched/core: Fix migration to invalid CPU in __set_cpus_allowed_ptr() (git fixes (sched)).
sched/core: Mitigate race cpus_share_cache()/update_top_cache_domain() (git fixes (sched)).
sched/fair: Do not balance task to its current running CPU (git fixes (sched)).
sched/rt: Minimize rq->lock contention in do_sched_rt_period_timer() (git fixes (sched)).
sched/rt: Restore rt_runtime after disabling RT_RUNTIME_SHARE (git fixes (sched)).
scsi: zfcp: Defer fc_rport blocking ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.155.1", rls:"SLES12.0SP5"))) {
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
