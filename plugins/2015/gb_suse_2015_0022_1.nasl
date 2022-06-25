###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0022_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen SUSE-SU-2015:0022-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851016");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:51:58 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-3495", "CVE-2014-5146", "CVE-2014-5149", "CVE-2014-8594",
                "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen SUSE-SU-2015:0022-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"xen was updated to fix nine security issues.

  These security issues were fixed:

  - Guest affectable page reference leak in MMU_MACHPHYS_UPDATE handling
  (CVE-2014-9030).

  - Insufficient bounding of 'REP MOVS' to MMIO emulated inside the
  hypervisor (CVE-2014-8867).

  - Excessive checking in compatibility mode hypercall argument translation
  (CVE-2014-8866).

  - Guest user mode triggerable VM exits not handled by hypervisor
  (bnc#9038500).

  - Missing privilege level checks in x86 emulation of far branches
  (CVE-2014-8595).

  - Insufficient restrictions on certain MMU update hypercalls
  (CVE-2014-8594).

  - Long latency virtual-mmu operations are not preemptible (CVE-2014-5146,
  CVE-2014-5149).

  - Intel VT-d Interrupt Remapping engines can be evaded by native NMI
  interrupts  (CVE-2013-3495).

  These non-security issues were fixed:

  - Corrupted save/restore test leaves orphaned data in xenstore
  (bnc#903357).

  - Temporary migration name is not cleaned up after migration (bnc#903359).

  - Xen save/restore of HVM guests cuts off disk and networking
  (bnc#866902).

  - increase limit domUloader to 32MB (bnc#901317).

  - XEN Host crashes when assigning non-VF device (SR-IOV) to guest
  (bnc#898772).

  - Windows 2012 R2 fails to boot up with greater than 60 vcpus (bnc#882089).

  - Restrict requires on grub2-x86_64-xen to x86_64 hosts

  - Change default dump directory (bsc#900292).

  - Update xen2libvirt.py to better detect and handle file formats

  - libxc: check return values on mmap() and madvise() on
  xc_alloc_hypercall_buffer() (bnc#897906).

  - Bug `xen-tools` uninstallable  grub2-x86_64-xen dependency not available
  (bnc#897614).

  - Adjust xentop column layout (bnc#896023).");
  script_tag(name:"affected", value:"xen on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.1_08_k3.12.28_4~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.1_08_k3.12.28_4~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.1_08~5.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.1_08_k3.12.28_4~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.1_08_k3.12.28_4~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.1_08~5.2", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
