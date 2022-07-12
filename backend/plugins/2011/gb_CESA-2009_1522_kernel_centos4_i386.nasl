###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1522 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016196.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880873");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2005-4881", "CVE-2009-3228");
  script_name("CentOS Update for kernel CESA-2009:1522 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kernel on CentOS 4");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * multiple, missing initialization flaws were found in the Linux kernel.
  Padding data in several core network structures was not initialized
  properly before being sent to user-space. These flaws could lead to
  information leaks. (CVE-2005-4881, CVE-2009-3228, Moderate)

  This update also fixes the following bugs:

  * a packet duplication issue was fixed via the RHSA-2008:0665 update.
  However, the fix introduced a problem for systems using network bonding:
  Backup slaves were unable to receive ARP packets. When using network
  bonding in the 'active-backup' mode and with the 'arp_validate=3' option,
  the bonding driver considered such backup slaves as being down (since they
  were not receiving ARP packets), preventing successful failover to these
  devices. (BZ#519384)

  * due to insufficient memory barriers in the network code, a process
  sleeping in select() may have missed notifications about new data. In rare
  cases, this bug may have caused a process to sleep forever. (BZ#519386)

  * the driver version number in the ata_piix driver was not changed between
  Red Hat Enterprise Linux 4.7 and Red Hat Enterprise Linux 4.8, even though
  changes had been made between these releases. This could have prevented the
  driver from loading on systems that check driver versions, as this driver
  appeared older than it was. (BZ#519389)

  * a bug in nlm_lookup_host() could have led to un-reclaimed locks on file
  systems, resulting in the umount command failing. This bug could have also
  prevented NFS services from being relocated correctly in clustered
  environments. (BZ#519656)

  * the data buffer ethtool_get_strings() allocated, for the igb driver, was
  smaller than the amount of data that was copied in igb_get_strings(),
  because of a miscalculation in IGB_QUEUE_STATS_LEN, resulting in memory
  corruption. This bug could have led to a kernel panic. (BZ#522738)

  * in some situations, write operations to a TTY device were blocked even
  when the O_NONBLOCK flag was used. A reported case of this issue occurred
  when a single TTY device was opened by two users (one using blocking mode,
  and the other using non-blocking mode). (BZ#523930)

  * a deadlock was found in the cciss driver. In rare cases, this caused an
  NMI lockup during boot. Messages such as 'cciss: controller cciss[x]
  failed, stopping.' and 'cciss[x]: controller not responding.' may have
  been displayed on the co ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.15.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
