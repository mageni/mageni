# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0112.1");
  script_cve_id("CVE-2020-26555", "CVE-2022-45887", "CVE-2023-1206", "CVE-2023-31085", "CVE-2023-3111", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39197", "CVE-2023-45863", "CVE-2023-51779", "CVE-2023-6606", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2024-01-18 04:20:23 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 22:51:48 +0000 (Fri, 09 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0112-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240112-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2020-26555: Fixed Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B that may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN (bsc#1179610 bsc#1215237).
CVE-2022-45887: Fixed a memory leak in ttusb_dec.c caused by the lack of a dvb_frontend_detach call (bsc#1205762).
CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup table which could be exploited by network adjacent attackers, increasing CPU usage by 95% (bsc#1212703).
CVE-2023-31085: Fixed a divide-by-zero error in do_div(sz,mtd->erasesize) that could cause a local DoS (bsc#1210778).
CVE-2023-3111: Fixed a use-after-free vulnerability in prepare_to_relocate in fs/btrfs/relocation.c (bsc#1212051).
CVE-2023-39189: Fixed a flaw in the Netfilter subsystem that could allow a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure (bsc#1216046).
CVE-2023-39192: Fixed an out of bounds read in the netfilter (bsc#1215858).
CVE-2023-39193: Fixed an out of bounds read in the xtables subsystem (bsc#1215860).
CVE-2023-39197: Fixed a out-of-bounds read in nf_conntrack_dccp_packet() (bsc#1216976).
CVE-2023-45863: Fixed a out-of-bounds write in fill_kobj_path() (bsc#1216058).
CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's ipv4: igmp component that could lead to local privilege escalation (bsc#1218253).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.150.1", rls:"SLES11.0SP4"))) {
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
