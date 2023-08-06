# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2805.1");
  script_cve_id("CVE-2017-5753", "CVE-2018-20784", "CVE-2022-3566", "CVE-2022-45884", "CVE-2022-45885", "CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2023-0590", "CVE-2023-1077", "CVE-2023-1095", "CVE-2023-1118", "CVE-2023-1249", "CVE-2023-1380", "CVE-2023-1390", "CVE-2023-1513", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-2194", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-2513", "CVE-2023-28328", "CVE-2023-28464", "CVE-2023-28772", "CVE-2023-30772", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-32269", "CVE-2023-35824");
  script_tag(name:"creation_date", value:"2023-07-12 04:21:59 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:28:00 +0000 (Wed, 02 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2805-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2805-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232805-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2805-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2017-5753: Fixed spectre vulnerability in prlimit (bsc#1209256).
CVE-2022-3566: Fixed race condition in the TCP Handler (bsc#1204405).
CVE-2022-45884: Fixed a use-after-free in dvbdev.c, related to dvb_register_device dynamically allocating fops (bsc#1205756).
CVE-2022-45885: Fixed a race condition in dvb_frontend.c that could cause a use-after-free when a device is disconnected (bsc#1205758).
CVE-2022-45886: Fixed a .disconnect versus dvb_device_open race condition in dvb_net.c that lead to a use-after-free (bsc#1205760).
CVE-2022-45887: Fixed a memory leak in ttusb_dec.c caused by the lack of a dvb_frontend_detach call (bsc#1205762).
CVE-2022-45919: Fixed a use-after-free in dvb_ca_en50221.c that could occur if there is a disconnect after an open, because of the lack of a wait_event (bsc#1205803).
CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could cause memory corruption (bsc#1208600).
CVE-2023-1095: Fixed a NULL pointer dereference in nf_tables due to zeroed list head (bsc#1208777).
CVE-2023-1118: Fixed a use-after-free bugs caused by ene_tx_irqsim() in media/rc (bsc#1208837).
CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that allowed a local user to crash the system (bsc#1209039).
CVE-2023-1380: Fixed a slab-out-of-bound read problem in brcmf_get_assoc_ies() (bsc#1209287).
CVE-2023-1390: Fixed remote DoS vulnerability in tipc_link_xmit() (bsc#1209289).
CVE-2023-1513: Fixed an uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an information leak (bsc#1209532).
CVE-2023-1611: Fixed an use-after-free flaw in btrfs_search_slot (bsc#1209687).
CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
CVE-2023-1989: Fixed a use after free in btsdio_remove (bsc#1210336).
CVE-2023-1990: Fixed a use after free in ndlc_remove (bsc#1210337).
CVE-2023-1998: Fixed a use after free during login when accessing the shost ipaddress (bsc#1210506).
CVE-2023-2124: Fixed an out-of-bound access in the XFS subsystem that could have lead to denial-of-service or potentially privilege escalation (bsc#1210498).
CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
CVE-2023-2194: Fixed an out-of-bounds write vulnerability in the SLIMpro I2C device driver (bsc#1210715).
CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler (bsc#1207036).
CVE-2023-23455: Fixed a denial of service inside atm_tc_enqueue in net/sched/sch_atm.c because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.205.1", rls:"SLES12.0SP2"))) {
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
