###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:0429 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017289.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880518");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4346", "CVE-2011-0521", "CVE-2011-0710", "CVE-2011-1010", "CVE-2011-1090", "CVE-2011-1478");
  script_name("CentOS Update for kernel CESA-2011:0429 centos5 i386");

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

  * A missing boundary check was found in the dvb_ca_ioctl() function in the
  Linux kernel's av7110 module. On systems that use old DVB cards that
  require the av7110 module, a local, unprivileged user could use this flaw
  to cause a denial of service or escalate their privileges. (CVE-2011-0521,
  Important)

  * An inconsistency was found in the interaction between the Linux kernel's
  method for allocating NFSv4 (Network File System version 4) ACL data and
  the method by which it was freed. This inconsistency led to a kernel panic
  which could be triggered by a local, unprivileged user with files owned by
  said user on an NFSv4 share. (CVE-2011-1090, Moderate)

  * A NULL pointer dereference flaw was found in the Generic Receive Offload
  (GRO) functionality in the Linux kernel's networking implementation. If
  both GRO and promiscuous mode were enabled on an interface in a virtual LAN
  (VLAN), it could result in a denial of service when a malformed VLAN frame
  is received on that interface. (CVE-2011-1478, Moderate)

  * A missing security check in the Linux kernel's implementation of the
  install_special_mapping() function could allow a local, unprivileged user
  to bypass the mmap_min_addr protection mechanism. (CVE-2010-4346, Low)

  * An information leak was found in the Linux kernel's task_show_regs()
  implementation. On IBM S/390 systems, a local, unprivileged user could use
  this flaw to read /proc/[PID]/status files, allowing them to discover the
  CPU register values of processes. (CVE-2011-0710, Low)

  * A missing validation check was found in the Linux kernel's
  mac_partition() implementation, used for supporting file systems created
  on Mac OS operating systems. A local attacker could use this flaw to cause
  a denial of service by mounting a disk that contains specially-crafted
  partitions. (CVE-2011-1010, Low)

  Red Hat would like to thank Ryan Sweat for reporting CVE-2011-1478, Tavis
  Ormandy for reporting CVE-2010-4346, and Timo Warns for reporting
  CVE-2011-1010.

  This update also fixes several bugs. Documentation for these bug fixes will
  be available shortly from the Technical Notes document linked to in the
  References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, and fix the bugs noted in the Technical
  Notes. The system must be rebooted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
