###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:1212 centos5 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017863.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881451");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:54:11 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2482", "CVE-2011-2491", "CVE-2011-2495", "CVE-2011-2517",
                "CVE-2011-2519", "CVE-2011-2901");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2011:1212 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A NULL pointer dereference flaw was found in the Linux kernel's Stream
  Control Transmission Protocol (SCTP) implementation. A remote attacker
  could send a specially-crafted SCTP packet to a target system, resulting in
  a denial of service. (CVE-2011-2482, Important)

  * A flaw in the Linux kernel's client-side NFS Lock Manager (NLM)
  implementation could allow a local, unprivileged user to cause a denial of
  service. (CVE-2011-2491, Important)

  * Buffer overflow flaws in the Linux kernel's netlink-based wireless
  configuration interface implementation could allow a local user, who has
  the CAP_NET_ADMIN capability, to cause a denial of service or escalate
  their privileges on systems that have an active wireless interface.
  (CVE-2011-2517, Important)

  * A flaw was found in the way the Linux kernel's Xen hypervisor
  implementation emulated the SAHF instruction. When using a
  fully-virtualized guest on a host that does not use hardware assisted
  paging (HAP), such as those running CPUs that do not have support for (or
  those that have it disabled) Intel Extended Page Tables (EPT) or AMD
  Virtualization (AMD-V) Rapid Virtualization Indexing (RVI), a privileged
  guest user could trigger this flaw to cause the hypervisor to crash.
  (CVE-2011-2519, Moderate)

  * An off-by-one flaw was found in the __addr_ok() macro in the Linux
  kernel's Xen hypervisor implementation when running on 64-bit systems. A
  privileged guest user could trigger this flaw to cause the hypervisor to
  crash. (CVE-2011-2901, Moderate)

  * /proc/[PID]/io is world-readable by default. Previously, these files
  could be read without any further restrictions. A local, unprivileged user
  could read these files, belonging to other, possibly privileged processes
  to gather confidential information, such as the length of a password used
  in a process. (CVE-2011-2495, Low)

  Red Hat would like to thank Vasily Averin for reporting CVE-2011-2491, and
  Vasiliy Kulikov of Openwall for reporting CVE-2011-2495.

  This update also fixes several bugs. Documentation for these bug fixes will
  be available shortly from the Technical Notes document linked to in the
  References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, and fix the bugs noted in the Technical
  Notes. The system must be rebooted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
