###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2010:0046 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016479.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880643");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-6304", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272");
  script_name("CentOS Update for kernel CESA-2010:0046 centos5 i386");

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

  * an array index error was found in the gdth driver. A local user could
  send a specially-crafted IOCTL request that would cause a denial of service
  or, possibly, privilege escalation. (CVE-2009-3080, Important)

  * a flaw was found in the FUSE implementation. When a system is low on
  memory, fuse_put_request() could dereference an invalid pointer, possibly
  leading to a local denial of service or privilege escalation.
  (CVE-2009-4021, Important)

  * Tavis Ormandy discovered a deficiency in the fasync_helper()
  implementation. This could allow a local, unprivileged user to leverage a
  use-after-free of locked, asynchronous file descriptors to cause a denial
  of service or privilege escalation. (CVE-2009-4141, Important)

  * the Parallels Virtuozzo Containers team reported the RHSA-2009:1243
  update introduced two flaws in the routing implementation. If an attacker
  was able to cause a large enough number of collisions in the routing hash
  table (via specially-crafted packets) for the emergency route flush to
  trigger, a deadlock could occur. Secondly, if the kernel routing cache was
  disabled, an uninitialized pointer would be left behind after a route
  lookup, leading to a kernel panic. (CVE-2009-4272, Important)

  * the RHSA-2009:0225 update introduced a rewrite attack flaw in the
  do_coredump() function. A local attacker able to guess the file name a
  process is going to dump its core to, prior to the process crashing, could
  use this flaw to append data to the dumped core file. This issue only
  affects systems that have '/proc/sys/fs/suid_dumpable' set to 2 (the
  default value is 0). (CVE-2006-6304, Moderate)

  The fix for CVE-2006-6304 changes the expected behavior: With suid_dumpable
  set to 2, the core file will not be recorded if the file already exists.
  For example, core files will not be overwritten on subsequent crashes of
  processes whose core files map to the same name.

  * an information leak was found in the Linux kernel. On AMD64 systems,
  32-bit processes could access and read certain 64-bit registers by
  temporarily switching themselves to 64-bit mode. (CVE-2009-2910, Moderate)

  * the RHBA-2008:0314 update introduced N_Port ID Virtualization (NPIV)
  support in the qla2xxx driver, resulting in two new sysfs pseudo files,
  '/sys/class/scsi_host/[a qla2xxx host]/vport_create' and 'vport_delete'.
  These two files were world-writable by default, allowing a local user to
  change SCSI host at ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
