###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:1065 centos5 x86_64
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
  script_oid("1.3.6.1.4.1.25623.1.0.881313");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:21:19 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1780", "CVE-2011-2525", "CVE-2011-2689");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2011:1065 centos5 x86_64");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017865.html");
  script_xref(name:"URL", value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/5.7_Technical_Notes/kernel.html#RHSA-2011-1065");

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

  * A flaw was found in the way the Xen hypervisor implementation handled
  instruction emulation during virtual machine exits. A malicious user-space
  process running in an SMP guest could trick the emulator into reading a
  different instruction than the one that caused the virtual machine to exit.
  An unprivileged guest user could trigger this flaw to crash the host. This
  only affects systems with both an AMD x86 processor and the AMD
  Virtualization (AMD-V) extensions enabled. (CVE-2011-1780, Important)

  * A flaw allowed the tc_fill_qdisc() function in the Linux kernel's packet
  scheduler API implementation to be called on built-in qdisc structures. A
  local, unprivileged user could use this flaw to trigger a NULL pointer
  dereference, resulting in a denial of service. (CVE-2011-2525, Moderate)

  * A flaw was found in the way space was allocated in the Linux kernel's
  Global File System 2 (GFS2) implementation. If the file system was almost
  full, and a local, unprivileged user made an fallocate() request, it could
  result in a denial of service. Note: Setting quotas to prevent users from
  using all available disk space would prevent exploitation of this flaw.
  (CVE-2011-2689, Moderate)

  These updated kernel packages include a number of bug fixes and
  enhancements. Space precludes documenting all of these changes in this
  advisory. Refer to the linked Red Hat Enterprise Linux 5.7 Technical Notes for
  information about the most significant bug fixes and enhancements included
  in this update.

  All Red Hat Enterprise Linux 5 users are advised to install these updated
  packages, which correct these issues. The system must be rebooted for this
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
