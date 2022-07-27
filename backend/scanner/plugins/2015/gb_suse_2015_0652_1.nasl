###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0652_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Linux SUSE-SU-2015:0652-1 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850994");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:19:17 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2010-5313", "CVE-2012-6657", "CVE-2013-4299", "CVE-2013-7263", "CVE-2014-0181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-8160", "CVE-2014-8709", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Linux SUSE-SU-2015:0652-1 (Linux)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 1 LTSS kernel was updated to fix
  security issues on kernels on the x86_64 architecture.

  The following security bugs have been fixed:

  * CVE-2013-4299: Interpretation conflict in
  drivers/md/dm-snap-persistent.c in the Linux kernel through 3.11.6
  allowed remote authenticated users to obtain sensitive information
  or modify data via a crafted mapping to a snapshot block device
  (bnc#846404).

  * CVE-2014-8160: SCTP firewalling failed until the SCTP module was
  loaded (bnc#913059).

  * CVE-2014-9584: The parse_rock_ridge_inode_internal function in
  fs/isofs/rock.c in the Linux kernel before 3.18.2 did not validate a
  length value in the Extensions Reference (ER) System Use Field,
  which allowed local users to obtain sensitive information from
  kernel memory via a crafted iso9660 image (bnc#912654).

  * CVE-2014-9585: The vdso_addr function in arch/x86/vdso/vma.c in the
  Linux kernel through 3.18.2 did not properly choose memory locations
  for the vDSO area, which made it easier for local users to bypass
  the ASLR protection mechanism by guessing a location at the end of a
  PMD (bnc#912705).

  * CVE-2014-9420: The rock_continue function in fs/isofs/rock.c in the
  Linux kernel through 3.18.1 did not restrict the number of Rock
  Ridge continuation entries, which allowed local users to cause a
  denial of service (infinite loop, and system crash or hang) via a
  crafted iso9660 image (bnc#911325).

  * CVE-2014-0181: The Netlink implementation in the Linux kernel
  through 3.14.1 did not provide a mechanism for authorizing socket
  operations based on the opener of a socket, which allowed local
  users to bypass intended access restrictions and modify network
  configurations by using a Netlink socket for the (1) stdout or (2)
  stderr of a setuid program (bnc#875051).

  * CVE-2010-5313: Race condition in arch/x86/kvm/x86.c in the Linux
  kernel before 2.6.38 allowed L2 guest OS users to cause a denial of
  service (L1 guest OS crash) via a crafted instruction that triggers
  an L2 emulation failure report, a similar issue to CVE-2014-7842
  (bnc#907822).

  * CVE-2014-7842: Race condition in arch/x86/kvm/x86.c in the Linux
  kernel before 3.17.4 allowed guest OS users to cause a denial of
  service (guest OS crash) via a crafted application that performs an
  MMIO transaction or a PIO transaction to trigger a guest userspace
  emulation error report, a similar issue to CVE-2010-5313
  (bnc#905312).

  * CVE-2014-3688: The SCTP implementation in the Linux kernel before
  3.17.4 allowed remote attackers to caus ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"Linux on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_18_2.6.32.59_0.19~0.9.17", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_18_2.6.32.59_0.19~0.9.17", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.19.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_18_2.6.32.59_0.19~0.9.17", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}