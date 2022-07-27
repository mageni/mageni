###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2010:0147 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016579.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880646");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0415", "CVE-2010-0437");
  script_name("CentOS Update for kernel CESA-2010:0147 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * a NULL pointer dereference flaw was found in the sctp_rcv_ootb() function
  in the Linux kernel Stream Control Transmission Protocol (SCTP)
  implementation. A remote attacker could send a specially-crafted SCTP
  packet to a target system, resulting in a denial of service.
  (CVE-2010-0008, Important)

  * a missing boundary check was found in the do_move_pages() function in
  the memory migration functionality in the Linux kernel. A local user could
  use this flaw to cause a local denial of service or an information leak.
  (CVE-2010-0415, Important)

  * a NULL pointer dereference flaw was found in the ip6_dst_lookup_tail()
  function in the Linux kernel. An attacker on the local network could
  trigger this flaw by sending IPv6 traffic to a target system, leading to a
  system crash (kernel OOPS) if dst->neighbour is NULL on the target system
  when receiving an IPv6 packet. (CVE-2010-0437, Important)

  * a NULL pointer dereference flaw was found in the ext4 file system code in
  the Linux kernel. A local attacker could use this flaw to trigger a local
  denial of service by mounting a specially-crafted, journal-less ext4 file
  system, if that file system forced an EROFS error. (CVE-2009-4308,
  Moderate)

  * an information leak was found in the print_fatal_signal() implementation
  in the Linux kernel. When '/proc/sys/kernel/print-fatal-signals' is set to
  1 (the default value is 0), memory that is reachable by the kernel could be
  leaked to user-space. This issue could also result in a system crash. Note
  that this flaw only affected the i386 architecture. (CVE-2010-0003,
  Moderate)

  * missing capability checks were found in the ebtables implementation, used
  for creating an Ethernet bridge firewall. This could allow a local,
  unprivileged user to bypass intended capability restrictions and modify
  ebtables rules. (CVE-2010-0007, Low)

  Bug fixes:

  * a bug prevented Wake on LAN (WoL) being enabled on certain Intel
  hardware. (BZ#543449)

  * a race issue in the Journaling Block Device. (BZ#553132)

  * programs compiled on x86, and that also call sched_rr_get_interval(),
  were silently corrupted when run on 64-bit systems. (BZ#557684)

  * the RHSA-2010:0019 update introduced a regression, preventing WoL from
  working for network devices using the e1000e driver. (BZ#559335)

  * adding a bonding interface in mode balance-alb to a bridge was not
  functional. (BZ#560588)

  * some KVM (Kernel-based Virtual Machine) guests ...

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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.15.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
