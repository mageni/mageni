# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3929.1");
  script_cve_id("CVE-2017-5753", "CVE-2018-13405", "CVE-2018-16882", "CVE-2020-0429", "CVE-2020-12655", "CVE-2020-14305", "CVE-2020-3702", "CVE-2021-20265", "CVE-2021-20322", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-34556", "CVE-2021-34981", "CVE-2021-3542", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-3715", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3760", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-3896", "CVE-2021-40490", "CVE-2021-42008", "CVE-2021-42739", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-12-07 08:23:32 +0000 (Tue, 07 Dec 2021)");
  script_version("2021-12-07T12:23:41+0000");
  script_tag(name:"last_modification", value:"2021-12-08 11:02:40 +0000 (Wed, 08 Dec 2021)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3929-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213929-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

Unprivileged BPF has been disabled by default to reduce attack surface
 as too many security issues have happened in the past (jsc#SLE-22573)

 You can re-enable via systemctl setting
/proc/sys/kernel/unprivileged_bpf_disabled to 0.
(kernel.unprivileged_bpf_disabled = 0)

CVE-2017-5753: Systems with microprocessors utilizing speculative
 execution and branch prediction may have allowed unauthorized disclosure
 of information to an attacker with local user access via a side-channel
 analysis (bnc#1068032). Additional spectrev1 fixes were added to the
 eBPF code.

CVE-2018-13405: The inode_init_owner function in fs/inode.c allowed
 local users to create files with an unintended group ownership, in a
 scenario where a directory is SGID to a certain group and is writable by
 a user who is not a member of that group. Here, the non-member can
 trigger creation of a plain file whose group ownership is that group.
 The intended behavior was that the non-member can trigger creation of a
 directory (but not a plain file) whose group ownership is that group.
 The non-member can escalate privileges by making the plain file
 executable and SGID (bnc#1087082 bnc#1100416 bnc#1129735).

CVE-2018-16882: A use-after-free issue was found in the way the KVM
 hypervisor processed posted interrupts when nested(=1) virtualization is
 enabled. In nested_get_vmcs12_pages(), in case of an error while
 processing posted interrupt address, it unmaps the 'pi_desc_page'
 without resetting 'pi_desc' descriptor address, which is later used in
 pi_test_and_clear_on(). A guest user/process could use this flaw to
 crash the host kernel resulting in DoS or potentially gain privileged
 access to a system. Kernel versions and are vulnerable (bnc#1119934).

CVE-2020-0429: In l2tp_session_delete and related functions of
 l2tp_core.c, there is possible memory corruption due to a use after
 free. This could lead to local escalation of privilege with System
 execution privileges needed. User interaction is not needed for
 exploitation (bnc#1176724).

CVE-2020-12655: An issue was discovered in xfs_agf_verify in
 fs/xfs/libxfs/xfs_alloc.c in the Linux kernel Attackers may trigger a
 sync of excessive duration via an XFS v5 image with crafted metadata,
 aka CID-d0c7feaf8767 (bnc#1171217).

CVE-2020-14305: An out-of-bounds memory write flaw was found in how the
 Linux kernel's Voice Over IP H.323 connection tracking
 functionality handled connections on ipv6 port 1720. This flaw allowed
 an unauthenticated remote user to crash the system, causing a denial of
 service. The highest threat from this vulnerability is to
 confidentiality, integrity, as well as system availability (bnc#1173346).

CVE-2020-3702: Specifically timed and handcrafted traffic can cause
 internal errors in a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.161.1", rls:"SLES12.0SP2"))) {
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
