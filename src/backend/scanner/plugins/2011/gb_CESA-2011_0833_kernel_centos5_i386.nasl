###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:0833 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017609.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880551");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2011-0726", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1763");
  script_name("CentOS Update for kernel CESA-2011:0833 centos5 i386");

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

  This update fixes the following security issues:

  * A flaw in the dccp_rcv_state_process() function could allow a remote
  attacker to cause a denial of service, even when the socket was already
  closed. (CVE-2011-1093, Important)

  * Multiple buffer overflow flaws were found in the Linux kernel's
  Management Module Support for Message Passing Technology (MPT) based
  controllers. A local, unprivileged user could use these flaws to cause a
  denial of service, an information leak, or escalate their privileges.
  (CVE-2011-1494, CVE-2011-1495, Important)

  * A missing validation of a null-terminated string data structure element
  in the bnep_sock_ioctl() function could allow a local user to cause an
  information leak or a denial of service. (CVE-2011-1079, Moderate)

  * Missing error checking in the way page tables were handled in the Xen
  hypervisor implementation could allow a privileged guest user to cause the
  host, and the guests, to lock up. (CVE-2011-1166, Moderate)

  * A flaw was found in the way the Xen hypervisor implementation checked for
  the upper boundary when getting a new event channel port. A privileged
  guest user could use this flaw to cause a denial of service or escalate
  their privileges. (CVE-2011-1763, Moderate)

  * The start_code and end_code values in '/proc/[pid]/stat' were not
  protected. In certain scenarios, this flaw could be used to defeat Address
  Space Layout Randomization (ASLR). (CVE-2011-0726, Low)

  * A missing initialization flaw in the sco_sock_getsockopt() function could
  allow a local, unprivileged user to cause an information leak.
  (CVE-2011-1078, Low)

  * A missing validation of a null-terminated string data structure element
  in the do_replace() function could allow a local user who has the
  CAP_NET_ADMIN capability to cause an information leak. (CVE-2011-1080, Low)

  * A buffer overflow flaw in the DEC Alpha OSF partition implementation in
  the Linux kernel could allow a local attacker to cause an information leak
  by mounting a disk that contains specially-crafted partition tables.
  (CVE-2011-1163, Low)

  * Missing validations of null-terminated string data structure elements in
  the do_replace(), compat_do_replace(), do_ipt_get_ctl(), do_ip6t_get_ctl(),
  and do_arpt_get_ctl() functions could allow a local user who has the
  CAP_NET_ADMIN capability to cause an information leak. (CVE-2011-1170,
  CVE-2011-1171, CVE-2011-1172, Low)

  * A heap overflow flaw in the Linux kernel's EFI GUID Partition ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
