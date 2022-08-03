# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2615.1");
  script_cve_id("CVE-2021-26341", "CVE-2021-33061", "CVE-2021-4204", "CVE-2021-44879", "CVE-2021-45402", "CVE-2022-0264", "CVE-2022-0494", "CVE-2022-0617", "CVE-2022-1012", "CVE-2022-1016", "CVE-2022-1184", "CVE-2022-1198", "CVE-2022-1205", "CVE-2022-1508", "CVE-2022-1651", "CVE-2022-1652", "CVE-2022-1671", "CVE-2022-1679", "CVE-2022-1729", "CVE-2022-1734", "CVE-2022-1789", "CVE-2022-1852", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-1974", "CVE-2022-1998", "CVE-2022-20132", "CVE-2022-20154", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-21499", "CVE-2022-2318", "CVE-2022-23222", "CVE-2022-26365", "CVE-2022-26490", "CVE-2022-29582", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-30594", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33981", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-08-02 04:46:45 +0000 (Tue, 02 Aug 2022)");
  script_version("2022-08-02T10:11:24+0000");
  script_tag(name:"last_modification", value:"2022-08-02 10:11:24 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2615-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222615-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated.

The following security bugs were fixed:

CVE-2022-29900, CVE-2022-29901: Fixed the RETBLEED attack, a new Spectre
 like Branch Target Buffer attack, that can leak arbitrary kernel
 information (bsc#1199657).

CVE-2022-34918: Fixed a buffer overflow with nft_set_elem_init() that
 could be used by a local attacker to escalate privileges (bnc#1201171).

CVE-2021-26341: Some AMD CPUs may transiently execute beyond
 unconditional direct branches, which may potentially result in data
 leakage (bsc#1201050).

CVE-2022-20154: Fixed a use after free due to a race condition in
 lock_sock_nested of sock.c. This could lead to local escalation of
 privilege with System execution privileges needed (bsc#1200599).

CVE-2022-2318: Fixed a use-after-free vulnerability in the timer
 handler in net/rose/rose_timer.c that allow attackers to crash the
 system without any privileges (bsc#1201251).

CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed
 multiple potential data leaks with Block and Network devices when using
 untrusted backends (bsc#1200762).

CVE-2022-33743: Fixed a Denial of Service related to XDP (bsc#1200763).

CVE-2022-1966: Fixed a use-after-free vulnerability in the Netfilter
 subsystem. This flaw allowed a local attacker with user access to cause
 a privilege escalation issue. (bnc#1200015)

CVE-2022-1852: Fixed a null-ptr-deref in the kvm module which can lead
 to DoS. (bsc#1199875)

CVE-2022-1789: Fixed a NULL pointer dereference when shadow paging is
 enabled. (bnc#1199674)

CVE-2022-1508: Fixed an out-of-bounds read flaw that could cause the
 system to crash. (bsc#1198968)

CVE-2022-1671: Fixed a null-ptr-deref bugs in net/rxrpc/server_key.c,
 unprivileged users could easily trigger it via ioctl. (bsc#1199439)

CVE-2022-1651: Fixed a bug in ACRN Device Model emulates virtual NICs in
 VM. This flaw may allow a local privileged attacker to leak kernel
 unauthorized information and also cause a denial of service problem.
 (bsc#1199433)

CVE-2022-29582: Fixed a use-after-free due to a race condition in
 io_uring timeouts. This can be triggered by a local user who has no
 access to any user namespace, however, the race condition perhaps can
 only be exploited infrequently. (bnc#1198811)

CVE-2022-0494: Fixed a kernel information leak flaw in the scsi_ioctl
 function. This flaw allowed a local attacker with a special user
 privilege to create issues with confidentiality. (bnc#1197386)

CVE-2021-4204: Fixed a vulnerability that allows local attackers to
 escalate privileges on affected installations via ebpf. (bnc#1194111)

CVE-2022-23222: Fixed a bug that allowed local users to gain privileges.
 (bnc#1194765)

CVE-2022-0264: Fixed a vulnerability in the Linux kernel's eBPF verifier
 when handling internal data structures. Internal memory locations could
 be returned to userspace. A local attacker with ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.7.1", rls:"SLES15.0SP4"))) {
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
