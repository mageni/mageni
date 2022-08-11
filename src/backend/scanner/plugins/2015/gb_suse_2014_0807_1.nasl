###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0807_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Linux SUSE-SU-2014:0807-1 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850881");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 13:28:57 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2012-6647", "CVE-2013-6382", "CVE-2013-6885", "CVE-2013-7027", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7339", "CVE-2014-0101", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1874", "CVE-2014-2523", "CVE-2014-2678", "CVE-2014-3122", "CVE-2014-3153");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Linux SUSE-SU-2014:0807-1 (Linux)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 SP1 LTSS kernel received a roll-up
  update to fix security and non-security issues.

  The following security issues have been fixed:

  *

  CVE-2014-3153: The futex acquisition code in kernel/futex.c can be
  used to gain ring0 access via the futex syscall. This could be used for
  privilege escalation for non root users. (bnc#880892)

  *

  CVE-2012-6647: The futex_wait_requeue_pi function in kernel/futex.c
  in the Linux kernel before 3.5.1 does not ensure that calls have two
  different futex addresses, which allows local users to cause a denial
  of service (NULL pointer dereference and system crash) or possibly
  have unspecified other impact via a crafted FUTEX_WAIT_REQUEUE_PI command.
  (bnc#878289)

  *

  CVE-2013-6382: Multiple buffer underflows in the XFS implementation
  in the Linux kernel through 3.12.1 allow local users to cause a denial of
  service (memory corruption) or possibly have unspecified
  other impact by leveraging the CAP_SYS_ADMIN capability for a (1)
  XFS_IOC_ATTRLIST_BY_HANDLE or (2) XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call
  with a crafted length value, related to the xfs_attrlist_by_handle
  function in fs/xfs/xfs_ioctl.c and the xfs_compat_attrlist_by_handle
  function in fs/xfs/xfs_ioctl32.c. (bnc#852553)

  *

  CVE-2013-6885: The microcode on AMD 16h 00h through 0Fh processors
  does not properly handle the interaction between locked instructions and
  write-combined memory types, which allows local users to cause a denial of
  service (system hang) via a crafted application, aka the errata 793 issue.
  (bnc#852967)

  *

  CVE-2013-7263: The Linux kernel before 3.12.4 updates certain length
  values before ensuring that associated data structures have been
  initialized, which allows local users to obtain sensitive information from
  kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
  system call, related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
  net/ipv6/raw.c, and net/ipv6/udp.c. (bnc#857643)

  *

  CVE-2013-7264: The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in
  the Linux kernel before 3.12.4 updates a certain length value before
  ensuring that an associated data structure has been initialized, which
  allows local users to obtain sensitive information from kernel stack
  memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.
  (bnc#857643)

  *

  CVE-2013-7265: The pn_recvmsg function in net/phonet/datagram.c in
  the Linux kernel before 3.12.4 updates a certain length value before
  ensuring that an associated data structure has ...

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

  if ((res = isrpmvuln(pkg:"btrfs-kmp-default-0", rpm:"btrfs-kmp-default-0~2.6.32.59_0.13~0.3.163", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ext4dev-kmp-default-0", rpm:"ext4dev-kmp-default-0~2.6.32.59_0.13~7.9.130", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ext4dev-kmp-trace-0", rpm:"ext4dev-kmp-trace-0~2.6.32.59_0.13~7.9.130", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"btrfs-kmp-xen-0", rpm:"btrfs-kmp-xen-0~2.6.32.59_0.13~0.3.163", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ext4dev-kmp-xen-0", rpm:"ext4dev-kmp-xen-0~2.6.32.59_0.13~7.9.130", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hyper-v-kmp-default-0", rpm:"hyper-v-kmp-default-0~2.6.32.59_0.13~0.18.39", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hyper-v-kmp-trace-0", rpm:"hyper-v-kmp-trace-0~2.6.32.59_0.13~0.18.39", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"btrfs-kmp-pae-0", rpm:"btrfs-kmp-pae-0~2.6.32.59_0.13~0.3.163", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ext4dev-kmp-pae-0", rpm:"ext4dev-kmp-pae-0~2.6.32.59_0.13~7.9.130", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hyper-v-kmp-pae-0", rpm:"hyper-v-kmp-pae-0~2.6.32.59_0.13~0.18.39", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.13.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}