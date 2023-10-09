# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3333.1");
  script_cve_id("CVE-2017-18344", "CVE-2018-3639", "CVE-2022-40982", "CVE-2022-45919", "CVE-2023-0459", "CVE-2023-20593", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3567", "CVE-2023-35824", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2023-08-16 13:18:27 +0000 (Wed, 16 Aug 2023)");
  script_version("2023-08-17T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-08-17 05:05:20 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:00 +0000 (Mon, 31 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233333-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-3268: Fixed an out of bounds memory access flaw in relay_file_read_start_pos in the relayfs (bsc#1212502).
CVE-2023-3776: Fixed improper refcount update in cls_fw leads to use-after-free (bsc#1213588).
CVE-2022-40982: Fixed transient execution attack called 'Gather Data Sampling' (bsc#1206418).
CVE-2023-3567: Fixed a use-after-free in vcs_read in drivers/tty/vt/vc_screen.c (bsc#1213167).
CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec (bsc#1211738).
CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
CVE-2018-3639: Fixed Speculative Store Bypass aka 'Memory Disambiguation' (bsc#1087082).
CVE-2017-18344: Fixed an OOB access led by an invalid check in timer_create. (bsc#1102851).
CVE-2022-45919: Fixed a use-after-free in dvb_ca_en50221.c that could occur if there is a disconnect after an open, because of the lack of a wait_event (bsc#1205803).
CVE-2023-35824: Fixed a use-after-free in dm1105_remove in drivers/media/pci/dm1105/dm1105.c (bsc#1212501).
CVE-2023-3161: Fixed shift-out-of-bounds in fbcon_set_font() (bsc#1212154).
CVE-2023-3141: Fixed a use-after-free flaw in r592_remove in drivers/memstick/host/r592.c, that allowed local attackers to crash the system at device disconnect (bsc#1212129).
CVE-2023-3159: Fixed use-after-free issue in driver/firewire in outbound_phy_packet_callback (bsc#1212128).

The following non-security bugs were fixed:

fbcon: Check font dimension limits (CVE-2023-3161 bsc#1212154).
firewire: fix potential uaf in outbound_phy_packet_callback() (CVE-2023-3159 bsc#1212128).
kABI: restore _copy_from_user on x86_64 and copy_to_user on x86 (bsc#1211738 CVE-2023-0459).
media: dm1105: Fix use after free bug in dm1105_remove due to race condition (bsc#1212501 CVE-2023-35824).
media: dvb-core: Fix use-after-free due to race condition at dvb_ca_en50221 (CVE-2022-45919 bsc#1205803).
memstick: r592: Fix UAF bug in r592_remove due to race condition (CVE-2023-3141 bsc#1212129 bsc#1211449).
net/sched: cls_fw: Fix improper refcount update leads to use-after-free (CVE-2023-3776 bsc#1213588).
pkt_sched: fix error return code in fw_change_attrs() (bsc#1213588).
pkt_sched: fix error return code in fw_change_attrs() (bsc#1213588).
posix-timer: Properly check sigevent->sigev_notify (CVE-2017-18344, bsc#1102851, bsc#1208715).
relayfs: fix out-of-bounds access in relay_file_read (bsc#1212502 CVE-2023-3268).
uaccess: Add speculation barrier to copy_from_user() (bsc#1211738 CVE-2023-0459).
vc_screen: don't clobber return value in vcs_read (bsc#1213167 CVE-2023-3567).
vc_screen: modify vcs_size() handling in vcs_read() (bsc#1213167 CVE-2023-3567).
vc_screen: move load of struct vc_data pointer in vcs_read() to avoid UAF ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.144.1", rls:"SLES11.0SP4"))) {
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
