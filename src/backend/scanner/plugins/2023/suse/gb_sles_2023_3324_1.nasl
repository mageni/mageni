# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3324.1");
  script_cve_id("CVE-2018-20784", "CVE-2018-3639", "CVE-2022-40982", "CVE-2023-0459", "CVE-2023-1637", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-2985", "CVE-2023-3106", "CVE-2023-3268", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3611", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2023-08-16 12:25:59 +0000 (Wed, 16 Aug 2023)");
  script_version("2023-08-17T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-08-17 05:05:20 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:28:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3324-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3324-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233324-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3324-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2018-20784: Fixed a denial of service (infinite loop in update_blocked_averages) by mishandled leaf cfs_rq in kernel/sched/fair.c (bsc#1126703).
CVE-2018-3639: Fixed Speculative Store Bypass aka 'Memory Disambiguation' (bsc#1087082).
CVE-2022-40982: Fixed transient execution attack called 'Gather Data Sampling' (bsc#1206418).
CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec (bsc#1211738).
CVE-2023-1637: Fixed vulnerability that could lead to unauthorized access to CPU memory after resuming CPU from suspend-to-RAM (bsc#1209779).
CVE-2023-20569: Fixed side channel attack 'Inception' or 'RAS Poisoning' (bsc#1213287).
CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in fs/hfsplus/super.c that could allow a local user to cause a denial of service (bsc#1211867).
CVE-2023-3106: Fixed crash in XFRM_MSG_GETSA netlink handler (bsc#1213251).
CVE-2023-3268: Fixed an out of bounds memory access flaw in relay_file_read_start_pos in the relayfs (bsc#1212502).
CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder that could allow a local attacker to escalate their privilege (bsc#1213059).
CVE-2023-3567: Fixed a use-after-free in vcs_read in drivers/tty/vt/vc_screen.c (bsc#1213167).
CVE-2023-3611: Fixed an out-of-bounds write in net/sched sch_qfq(bsc#1213585).
CVE-2023-3776: Fixed improper refcount update in cls_fw leads to use-after-free (bsc#1213588).

The following non-security bugs were fixed:

net/sched: sch_qfq: refactor parsing of netlink parameters (bsc#1213585).
ubi: Fix failure attaching when vid_hdr offset equals to (sub)page size (bsc#1210584).
ubi: ensure that VID header offset + VID header size &lt,= alloc, size (bsc#1210584).
x86: Treat R_X86_64_PLT32 as R_X86_64_PC32 (git-fixes) No it's not git-fixes it's used to make sle12-sp2 compile with newer toolchain to make the life of all the poor souls maintaining this ancient kernel on their modern machines, a little bit easier.");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.208.1", rls:"SLES12.0SP2"))) {
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
