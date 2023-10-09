# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3349.1");
  script_cve_id("CVE-2018-3639", "CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-2985", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2023-08-18 04:21:54 +0000 (Fri, 18 Aug 2023)");
  script_version("2023-08-18T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-08-18 05:05:27 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:00 +0000 (Mon, 31 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3349-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3349-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233349-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3349-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-3609: Fixed reference counter leak leading to overflow in net/sched (bsc#1213586).
CVE-2023-3611: Fixed an out-of-bounds write in net/sched sch_qfq(bsc#1213585).
CVE-2023-3567: Fixed a use-after-free in vcs_read in drivers/tty/vt/vc_screen.c (bsc#1213167).
CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec (bsc#1211738).
CVE-2022-40982: Fixed transient execution attack called 'Gather Data Sampling' (bsc#1206418).
CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in fs/hfsplus/super.c that could allow a local user to cause a denial of service (bsc#1211867).
CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder that could allow a local attacker to escalate their privilege (bsc#1213059).
CVE-2023-20569: Fixed side channel attack 'Inception' or 'RAS Poisoning' (bsc#1213287).

The following non-security bugs were fixed:

Get module prefix from kmod (bsc#1212835).
USB: add NO_LPM quirk for Realforce 87U Keyboard (git-fixes).
USB: core: add quirk for Alcor Link AK9563 smartcard reader (git-fixes).
USB: core: hub: Disable autosuspend for Cypress CY7C65632 (git-fixes).
USB: hcd-pci: Fully suspend across freeze/thaw cycle (git-fixes).
USB: hub: Add delay for SuperSpeed hub resume to let links transit to U0 (git-fixes).
USB: serial: option: add Fibocom FM160 0x0111 composition (git-fixes).
USB: serial: option: add Quectel EM05-G (GR) modem (git-fixes).
USB: serial: option: add Quectel EM05-G (RS) modem (git-fixes).
USB: serial: option: add Sierra Wireless EM9191 (git-fixes).
USB: serial: option: add u-blox LARA-R6 00B modem (git-fixes).
blkcg, writeback: dead memcgs shouldn't contribute to writeback ownership arbitration (bsc#1213022).
btrfs: fix resolving backrefs for inline extent followed by prealloc (bsc#1213133).
delete suse/memcg-drop-kmem-limit_in_bytes. drop the patch in order to fix bsc#1213705.
dlm: Delete an unnecessary variable initialisation in dlm_ls_start() (git-fixes).
dlm: NULL check before kmem_cache_destroy is not needed (git-fixes).
dlm: fix invalid cluster name warning (git-fixes).
dlm: fix missing idr_destroy for recover_idr (git-fixes).
dlm: fix missing lkb refcount handling (git-fixes).
dlm: fix plock invalid read (git-fixes).
dlm: fix possible call to kfree() for non-initialized pointer (git-fixes).
ext4: Fix reusing stale buffer heads from last failed mounting (bsc#1213020).
ext4: add inode table check in __ext4_get_inode_loc to aovid possible infinite loop (bsc#1207617).
ext4: avoid BUG_ON when creating xattrs (bsc#1205496).
ext4: avoid unaccounted block allocation when expanding inode (bsc#1207634).
ext4: bail ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.146.1", rls:"SLES12.0SP5"))) {
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
