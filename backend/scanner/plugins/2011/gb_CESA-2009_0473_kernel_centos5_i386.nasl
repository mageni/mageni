###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:0473 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015845.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880841");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2008-4307", "CVE-2009-0787", "CVE-2009-0834", "CVE-2009-1336", "CVE-2009-1337");
  script_name("CentOS Update for kernel CESA-2009:0473 centos5 i386");

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

  * the exit_notify() function in the Linux kernel did not properly reset the
  exit signal if a process executed a set user ID (setuid) application before
  exiting. This could allow a local, unprivileged user to elevate their
  privileges. (CVE-2009-1337, Important)

  * a flaw was found in the ecryptfs_write_metadata_to_contents() function of
  the Linux kernel eCryptfs implementation. On systems with a 4096 byte
  page-size, this flaw may have caused 4096 bytes of uninitialized kernel
  memory to be written into the eCryptfs file headers, leading to an
  information leak. Note: Encrypted files created on systems running the
  vulnerable version of eCryptfs may contain leaked data in the eCryptfs file
  headers. This update does not remove any leaked data. Refer to the
  Knowledgebase article in the References section for further information.
  (CVE-2009-0787, Moderate)

  * the Linux kernel implementation of the Network File System (NFS) did not
  properly initialize the file name limit in the nfs_server data structure.
  This flaw could possibly lead to a denial of service on a client mounting
  an NFS share. (CVE-2009-1336, Moderate)

  This update also fixes the following bugs:

  * the enic driver (Cisco 10G Ethernet) did not operate under
  virtualization. (BZ#472474)

  * network interfaces using the IBM eHEA Ethernet device driver could not be
  successfully configured under low-memory conditions. (BZ#487035)

  * bonding with the 'arp_validate=3' option may have prevented fail overs.
  (BZ#488064)

  * when running under virtualization, the acpi-cpufreq module wrote 'Domain
  attempted WRMSR' errors to the dmesg log. (BZ#488928)

  * NFS clients may have experienced deadlocks during unmount. (BZ#488929)

  * the ixgbe drive ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~128.1.10.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
