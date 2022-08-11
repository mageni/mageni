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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2720.1");
  script_cve_id("CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-10 04:21:08 +0000 (Wed, 10 Aug 2022)");
  script_version("2022-08-10T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-08-10 10:11:40 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 13:44:00 +0000 (Thu, 28 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2720-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2720-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222720-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2720-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-36946: Fixed an incorrect packet trucation operation which
 could lead to denial of service (bnc#1201940).

CVE-2022-20166: Fixed several possible memory safety issues due to
 unsafe operations (bsc#1200598).

CVE-2020-36558: Fixed a race condition involving VT_RESIZEX which could
 lead to a NULL pointer dereference and general protection fault
 (bnc#1200910).

CVE-2020-36557: Fixed a race condition between the VT_DISALLOCATE ioctl
 and closing/opening of TTYs could lead to a use-after-free (bnc#1201429).

CVE-2021-33656: Fixed memory out of bounds write related to ioctl cmd
 PIO_FONT (bnc#1201636).

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2022-1462: Fixed an out-of-bounds read flaw in the TTY subsystem
 (bnc#1198829).

The following non-security bugs were fixed:

Add missing recommends of kernel-install-tools (bsc#1200442)

qla2xxx: drop patch which prevented nvme port discovery (bsc#1200651
 bsc#1200644 bsc#1201954 bsc#1201958).

kvm: emulate: do not adjust size of fastop and setcc subroutines
 (bsc#1201930).

nfs: avoid NULL pointer dereference when there is unflushed data
 (bsc#1201196).

kvm: emulate: Fix SETcc emulation function offsets with SLS
 (bsc#1201930).

lkdtm: Disable return thunks in rodata.c (bsc#1114648).

powerpc/64: Move paca allocation later in boot (bsc#1190812).

powerpc/fadump: fix PT_LOAD segment for boot memory area (bsc#1103269
 ltc#169948).

powerpc/fadump: make crash memory ranges array allocation generic
 (bsc#1103269 ltc#169948).

powerpc: Set crashkernel offset to mid of RMA region (bsc#1190812).

rpm/kernel-obs-build.spec.in: Also depend on dracut-systemd (bsc#1195775)

rpm/kernel-obs-build.spec.in: add systemd-initrd and terminfo dracut
 module (bsc#1195775)

rpm/kernel-obs-build.spec.in: use default dracut modules (bsc#1195926,
 bsc#1198484) Let's iron out the reduced initrd optimisation in
 Tumbleweed. Build full blown dracut initrd with systemd for SLE15 SP4.

scsi: qla2xxx: Add a new v2 dport diagnostic feature (bsc#1201958).

scsi: qla2xxx: Add debug prints in the device remove path (bsc#1201958).

scsi: qla2xxx: Check correct variable in qla24xx_async_gffid()
 (bsc#1201958).

scsi: qla2xxx: Fix crash due to stale SRB access around I/O timeouts
 (bsc#1201958).

scsi: qla2xxx: Fix discovery issues in FC-AL topology (bsc#1201651).

scsi: qla2xxx: Fix erroneous mailbox timeout after PCI error injection
 (bsc#1201958).

scsi: qla2xxx: Fix excessive I/O error messages by default (bsc#1201958).

scsi: qla2xxx: Fix imbalance vha->vref_count (bsc#1201651).

scsi: qla2xxx: Fix incorrect display of max frame size (bsc#1201958).

scsi: qla2xxx: Fix losing FCP-2 targets during port perturbation tests
 (bsc#1201958).

scsi: qla2xxx: Fix losing FCP-2 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.106.1", rls:"SLES12.0SP5"))) {
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
