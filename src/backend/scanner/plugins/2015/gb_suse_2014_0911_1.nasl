###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0911_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Linux SUSE-SU-2014:0911-1 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850821");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2012-2372", "CVE-2013-2929", "CVE-2013-4299", "CVE-2013-4579", "CVE-2013-6382", "CVE-2013-7339", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-0131", "CVE-2014-0155", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1874", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2678", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4699", "CVE-2014-4508");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Linux SUSE-SU-2014:0911-1 (Linux)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to fix
  various bugs and security issues.

  The following security bugs have been fixed:

  *

  CVE-2012-2372: The rds_ib_xmit function in net/rds/ib_send.c in the
  Reliable Datagram Sockets (RDS) protocol implementation in the Linux
  kernel 3.7.4 and earlier allows local users to cause a denial of service
  (BUG_ON and kernel panic) by establishing an RDS connection with the
  source IP address equal to the IPoIB interfaces own IP address, as
  demonstrated by rds-ping. (bnc#767610)

  *

  CVE-2013-2929: The Linux kernel before 3.12.2 does not properly use
  the get_dumpable function, which allows local users to bypass intended
  ptrace restrictions or obtain sensitive information from IA64 scratch
  registers via a crafted application, related to kernel/ptrace.c and
  arch/ia64/include/asm/processor.h. (bnc#847652)

  *

  CVE-2013-4299: Interpretation conflict in
  drivers/md/dm-snap-persistent.c in the Linux kernel through 3.11.6 allows
  remote authenticated users to obtain sensitive information or modify data
  via a crafted mapping to a snapshot block device. (bnc#846404)

  *

  CVE-2013-4579: The ath9k_htc_set_bssid_mask function in
  drivers/net/wireless/ath/ath9k/htc_drv_main.c in the Linux kernel through
  3.12 uses a BSSID masking approach to determine the set of MAC addresses
  on which a Wi-Fi device is listening, which allows remote attackers to
  discover the original MAC address after spoofing by sending a series of
  packets to MAC addresses with certain bit manipulations. (bnc#851426)

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

  CVE-2013-7339: The rds_ib_laddr_check function in net/rds/ib.c in
  the Linux kernel before 3.12.8 allows local users to cause a denial of
  service (NULL pointer dereference and system crash) or possibly have
  unspecified other impact via a bind system call for an RDS socket on a
  system that lacks RDS transports. (bnc#869563)

  *

  CVE-2014-0055: The get_rx_bufs function in drivers/vhost/net.c in
  the vhost-net subsystem in the Linux kernel packag ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"Linux on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_02_3.0.101_0.35~0.7.45", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.35.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_02_3.0.101_0.35~0.7.45", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
