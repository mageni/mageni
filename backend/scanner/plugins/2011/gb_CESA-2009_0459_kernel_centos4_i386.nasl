###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:0459 centos4 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015839.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880941");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-4307", "CVE-2009-0028", "CVE-2009-0676", "CVE-2009-0834");
  script_name("CentOS Update for kernel CESA-2009:0459 centos4 i386");

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

  Security fixes:

  * a logic error was found in the do_setlk() function of the Linux kernel
  Network File System (NFS) implementation. If a signal interrupted a lock
  request, the local POSIX lock was incorrectly created. This could cause a
  denial of service on the NFS server if a file descriptor was closed before
  its corresponding lock request returned. (CVE-2008-4307, Important)

  * a deficiency was found in the Linux kernel system call auditing
  implementation on 64-bit systems. This could allow a local, unprivileged
  user to circumvent a system call audit configuration, if that configuration
  filtered based on the 'syscall' number or arguments.
  (CVE-2009-0834, Important)

  * Chris Evans reported a deficiency in the Linux kernel signals
  implementation. The clone() system call permits the caller to indicate the
  signal it wants to receive when its child exits. When clone() is called
  with the CLONE_PARENT flag, it permits the caller to clone a new child that
  shares the same parent as itself, enabling the indicated signal to be sent
  to the caller's parent (instead of the caller), even if the caller's parent
  has different real and effective user IDs. This could lead to a denial of
  service of the parent. (CVE-2009-0028, Moderate)

  * the sock_getsockopt() function in the Linux kernel did not properly
  initialize a data structure that can be directly returned to user-space
  when the getsockopt() function is called with SO_BSDCOMPAT optname set.
  This flaw could possibly lead to memory disclosure.
  (CVE-2009-0676, Moderate)

  Bug fixes:

  * a kernel crash may have occurred for Red Hat Enterprise Linux 4.7 guests
  if their guest configuration file specified 'vif = [ 'type=ioemu' ]'. This
  crash only occurred when starting guests via the 'xm create' command.
  (BZ#477146)

  * a bug in IO-APIC NMI watchdog may have prevented Red Hat Enterprise Linux
  4.7 from being installed on HP ProLiant DL580 G5 systems. Hangs during
  installation and 'NMI received for unknown reason [xx]' errors may have
  occurred. (BZ#479184)

  * a kernel deadlock on some systems when using netdump through a network
  interface that uses the igb driver. (BZ#480579)

  * a possible kernel hang in sys_ptrace() on the Itanium architecture,
  possibly triggered by tracing a threaded process with strace. (BZ#484904)

  * the RHSA-2008:0665 errata only fixed the known problem with the LSI Logic
  LSI53C1030 Ultra320 SCSI controller, for ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~78.0.22.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
