###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for Red Hat Enterprise Linux 5.6 kernel RHSA-2011:0017-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870378");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3296", "CVE-2010-3877", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4158", "CVE-2010-4238", "CVE-2010-4243", "CVE-2010-4255", "CVE-2010-4263", "CVE-2010-4343", "CVE-2010-4258");
  script_name("RedHat Update for Red Hat Enterprise Linux 5.6 kernel RHSA-2011:0017-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Red Hat Enterprise Linux 5.6 kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"Red Hat Enterprise Linux 5.6 kernel on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A NULL pointer dereference flaw was found in the igb driver in the Linux
  kernel. If both the Single Root I/O Virtualization (SR-IOV) feature and
  promiscuous mode were enabled on an interface using igb, it could result in
  a denial of service when a tagged VLAN packet is received on that
  interface. (CVE-2010-4263, Important)

  * A missing sanity check was found in vbd_create() in the Xen hypervisor
  implementation. As CD-ROM drives are not supported by the blkback back-end
  driver, attempting to use a virtual CD-ROM drive with blkback could trigger
  a denial of service (crash) on the host system running the Xen hypervisor.
  (CVE-2010-4238, Moderate)

  * A flaw was found in the Linux kernel execve() system call implementation.
  A local, unprivileged user could cause large amounts of memory to be
  allocated but not visible to the OOM (Out of Memory) killer, triggering a
  denial of service. (CVE-2010-4243, Moderate)

  * A flaw was found in fixup_page_fault() in the Xen hypervisor
  implementation. If a 64-bit para-virtualized guest accessed a certain area
  of memory, it could cause a denial of service on the host system running
  the Xen hypervisor. (CVE-2010-4255, Moderate)

  * A missing initialization flaw was found in the bfa driver used by Brocade
  Fibre Channel Host Bus Adapters. A local, unprivileged user could use this
  flaw to cause a denial of service by reading a file in the
  '/sys/class/fc_host/host#/statistics/' directory. (CVE-2010-4343, Moderate)

  * Missing initialization flaws in the Linux kernel could lead to
  information leaks. (CVE-2010-3296, CVE-2010-3877, CVE-2010-4072,
  CVE-2010-4073, CVE-2010-4075, CVE-2010-4080, CVE-2010-4081, CVE-2010-4158,
  Low)

  Red Hat would like to thank Kosuke Tatsukawa for reporting CVE-2010-4263,
  Vladymyr Denysov for reporting CVE-2010-4238, Brad Spengler for reporting
  CVE-2010-4243, Dan Rosenberg for reporting CVE-2010-3296, CVE-2010-4073,
  CVE-2010-4075, CVE-2010-4080, CVE-2010-4081, and CVE-2010-4158, Vasiliy
  Kulikov for reporting CVE-2010-3877, and Kees Cook for reporting
  CVE-2010-4072.

  These updated packages also include several hundred bug fixes for and
  enhancements to the Linux kernel. Space precludes documenting each of these
  changes in this advisory and users are directed to the Red Hat Enterprise
  Linux 5.6 Release Notes for information on the most significant of these
 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
