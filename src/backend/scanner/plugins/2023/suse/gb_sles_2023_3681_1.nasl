# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3681.1");
  script_cve_id("CVE-2022-36402", "CVE-2023-2007", "CVE-2023-20588", "CVE-2023-34319", "CVE-2023-3772", "CVE-2023-3812", "CVE-2023-3863", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4132", "CVE-2023-4133", "CVE-2023-4134", "CVE-2023-4194", "CVE-2023-4385", "CVE-2023-4387", "CVE-2023-4459");
  script_tag(name:"creation_date", value:"2023-09-20 04:21:30 +0000 (Wed, 20 Sep 2023)");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 20:32:00 +0000 (Wed, 16 Aug 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3681-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3681-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233681-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3681-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2022-36402: Fixed an integer overflow vulnerability in vmwgfx driver in that allowed a local attacker with a user account on the system to gain privilege, causing a denial of service (bsc#1203517).
CVE-2023-2007: Fixed a flaw in the DPT I2O Controller driver that could allow an attacker to escalate privileges and execute arbitrary code in the context of the kernel (bsc#1210448).
CVE-2023-3772: Fixed a flaw in XFRM subsystem that may have allowed a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer leading to a possible kernel crash and denial of service (bsc#1213666).
CVE-2023-3812: Fixed an out-of-bounds memory access flaw in the TUN/TAP device driver functionality that could allow a local user to crash or potentially escalate their privileges on the system (bsc#1213543).
CVE-2023-3863: Fixed a use-after-free flaw was found in nfc_llcp_find_local that allowed a local user with special privileges to impact a kernel information leak issue (bsc#1213601).
CVE-2023-4128: Fixed a use-after-free flaw in net/sched/cls_fw.c that allowed a local attacker to perform a local privilege escalation due to incorrect handling of the existing filter, leading to a kernel information leak issue (bsc#1214149).
CVE-2023-4132: Fixed use-after-free vulnerability was found in the siano smsusb module that allowed a local user to crash the system, causing a denial of service condition (bsc#1213969).
CVE-2023-4133: Fixed use after free bugs caused by circular dependency problem in cxgb4 (bsc#1213970).
CVE-2023-4134: Fixed use-after-free in cyttsp4_watchdog_work() (bsc#1213971).
CVE-2023-4194: Fixed a type confusion in net tun_chr_open() (bsc#1214019).
CVE-2023-4385: Fixed a NULL pointer dereference flaw in dbFree that may have allowed a local attacker to crash the system due to a missing sanity check (bsc#1214348).
CVE-2023-4387: Fixed use-after-free flaw in vmxnet3_rq_alloc_rx_buf that could allow a local attacker to crash the system due to a double-free (bsc#1214350).
CVE-2023-4459: Fixed a NULL pointer dereference flaw in vmxnet3_rq_cleanup that may have allowed a local attacker with normal user privilege to cause a denial of service (bsc#1214451).
CVE-2023-20588: Fixed a division-by-zero error on some AMD processors that can potentially return speculative data resulting in loss of confidentiality (bsc#1213927).
CVE-2023-34319: Fixed buffer overrun triggered by unusual packet in xen/netback (XSA-432) (bsc#1213546).
CVE-2023-40283: Fixed use-after-free in l2cap_sock_ready_cb (bsc#1214233).

The following non-security bugs were fixed:

ARM: spear: Do not use timer namespace for timer_shutdown() function (bsc#1213970).
Bluetooth: nokia: fix value check in nokia_bluetooth_serdev_probe() (git-fixes).
Revert 'scsi: qla2xxx: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.149.1", rls:"SLES12.0SP5"))) {
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
