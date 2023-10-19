# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4032.1");
  script_cve_id("CVE-2020-36766", "CVE-2023-1192", "CVE-2023-1206", "CVE-2023-1859", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-42754", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2023-10-11 04:21:15 +0000 (Wed, 11 Oct 2023)");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:00 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4032-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234032-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-39194: Fixed a flaw in the processing of state filters which could allow a local attackers to disclose sensitive information. (bsc#1215861)
CVE-2023-39193: Fixed a flaw in the processing of state filters which could allow a local attackers to disclose sensitive information. (bsc#1215860)
CVE-2023-39192: Fixed a flaw in the u32_match_it function which could allow a local attackers to disclose sensitive information. (bsc#1215858)
CVE-2023-42754: Fixed a null pointer dereference in ipv4_link_failure which could lead an authenticated attacker to trigger a DoS. (bsc#1215467)
CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup table. A user located in the local network or with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up to 95% (bsc#1212703).
CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network scheduler which could be exploited to achieve local privilege escalatio (bsc#1215275).
CVE-2023-4622: Fixed a use-after-free vulnerability in the Unix domain sockets component which could be exploited to achieve local privilege escalation (bsc#1215117).
CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler which could be exploited to achieve local privilege escalation (bsc#1215115).
CVE-2020-36766: Fixed a potential information leak in in the CEC driver (bsc#1215299).
CVE-2023-1859: Fixed a use-after-free flaw in Xen transport for 9pfs which could be exploited to crash the system (bsc#1210169).
CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential information disclosure or a denial of service (bsc#1215221).
CVE-2023-1192: Fixed use-after-free in cifs_demultiplex_thread() (bsc#1208995).

The following non-security bugs were fixed:

9p/trans_virtio: Remove sysfs file on probe failure (git-fixes).
arm64: insn: Fix ldadd instruction encoding (git-fixes)
arm64: kgdb: Set PSTATE.SS to 1 to re-enable single-step (git-fixes)
blk-mq: Add blk_mq_delay_run_hw_queues() API call (bsc#1214586).
blk-mq: In blk_mq_dispatch_rq_list() 'no budget' is a reason to kick (bsc#1214586).
blk-mq: Rerun dispatching in the case of budget contention (bsc#1214586).
check-for-config-changes: ignore BUILTIN_RETURN_ADDRESS_STRIPS_PAC (bsc#1214380). gcc7 on SLE 15 does not support this while later gcc does.
direct-io: allow direct writes to empty inodes (bsc#1215164).
Drivers: hv: vmbus: Do not dereference ACPI root object handle (git-fixes).
drm/ast: Fix DRAM init on AST2200 (bsc#1152446)
drm/client: Fix memory leak in drm_client_target_cloned (bsc#1152446) Backporting changes: * move changes to drm_fb_helper.c * context changes drm/client: Send hotplug event after registering a client (bsc#1152446) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.152.1", rls:"SLES12.0SP5"))) {
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
