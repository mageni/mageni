###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1106 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/015975.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880750");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");
  script_name("CentOS Update for kernel CESA-2009:1106 centos5 i386");

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

  * several flaws were found in the way the Linux kernel CIFS implementation
  handles Unicode strings. CIFS clients convert Unicode strings sent by a
  server to their local character sets, and then write those strings into
  memory. If a malicious server sent a long enough string, it could write
  past the end of the target memory region and corrupt other memory areas,
  possibly leading to a denial of service or privilege escalation on the
  client mounting the CIFS share. (CVE-2009-1439, CVE-2009-1633, Important)

  * the Linux kernel Network File System daemon (nfsd) implementation did not
  drop the CAP_MKNOD capability when handling requests from local,
  unprivileged users. This flaw could possibly lead to an information leak or
  privilege escalation. (CVE-2009-1072, Moderate)

  * Frank Filz reported the NFSv4 client was missing a file permission check
  for the execute bit in some situations. This could allow local,
  unprivileged users to run non-executable files on NFSv4 mounted file
  systems. (CVE-2009-1630, Moderate)

  * a missing check was found in the hypervisor_callback() function in the
  Linux kernel provided by the kernel-xen package. This could cause a denial
  of service of a 32-bit guest if an application running in that guest
  accesses a certain memory location in the kernel. (CVE-2009-1758, Moderate)

  * a flaw was found in the AGPGART driver. The agp_generic_alloc_page() and
  agp_generic_alloc_pages() functions did not zero out the memory pages they
  allocate, which may later be available to user-space processes. This flaw
  could possibly lead to an information leak. (CVE-2009-1192, Low)

  Bug fixes:

  * a race in the NFS client between destroying cached access rights and
  unmounting an NFS file system could have caused a system crash. 'Busy
  inodes' messages may have been logged. (BZ#498653)

  * nanosleep() could sleep several milliseconds less than the specified time
  on Intel Itanium-based systems. (BZ#500349)

  * LEDs for disk drives in AHCI mode may have displayed a fault state when
  there were no faults. (BZ#500120)

  * ptrace_do_wait() reported tasks were stopped each time the process doing
  the trace called wait(), instead of reporting it once. (BZ#486945)

  * epoll_wait() may have caused a system lockup and problems for
  applications. (BZ#497322)

  * missing capabilities could possibly allow users with an fsuid other than
  0 to perform actions on some file system types that would otherwise be
  pr ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.14.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
