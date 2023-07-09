# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2506.1");
  script_cve_id("CVE-2017-5753", "CVE-2018-9517", "CVE-2022-3567", "CVE-2023-0590", "CVE-2023-1118", "CVE-2023-1513", "CVE-2023-1670", "CVE-2023-1989", "CVE-2023-2162", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-23559", "CVE-2023-28328", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2023-06-15 04:21:58 +0000 (Thu, 15 Jun 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:29:00 +0000 (Mon, 23 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2506-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2506-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232506-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2506-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 LTSS EXTREME CORE kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
CVE-2023-32269: Fixed a use-after-free in af_netrom.c, related to the fact that accept() was also allowed for a successfully connected AF_NETROM socket (bsc#1211186).
CVE-2023-1989: Fixed a use after free in btsdio_remove (bsc#1210336).
CVE-2017-5753: Fixed spectre vulnerability in prlimit (bsc#1209256).
CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
CVE-2023-1513: Fixed an uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an information leak (bsc#1209532).
CVE-2023-28328: Fixed a denial of service issue in az6027 driver in drivers/media/usb/dev-usb/az6027.c (bsc#1209291).
CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
CVE-2018-9517: Fixed possible memory corruption due to a use after free in pppol2tp_connect (bsc#1108488).
CVE-2023-1118: Fixed a use-after-free bugs caused by ene_tx_irqsim() in media/rc (bsc#1208837).
CVE-2023-23559: Fixed integer overflow in rndis_wlan that leads to a buffer overflow (bsc#1207051).
CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler (bsc#1207036).
CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in net/sched/sch_atm.c because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results) (bsc#1207125).
CVE-2022-3567: Fixed a to race condition in inet6_stream_ops()/inet6_dgram_ops() (bsc#1204414).

The following non-security bugs were fixed:

Do not sign the vanilla kernel (bsc#1209008).
do not fallthrough in cbq_classify and stop on TC_ACT_SHOT");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.141.1", rls:"SLES11.0SP4"))) {
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
