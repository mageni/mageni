###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1548 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-November/016304.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880731");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613");
  script_name("CentOS Update for kernel CESA-2009:1548 centos5 i386");

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

  * a system with SELinux enforced was more permissive in allowing local
  users in the unconfined_t domain to map low memory areas even if the
  mmap_min_addr restriction was enabled. This could aid in the local
  exploitation of NULL pointer dereference bugs. (CVE-2009-2695, Important)

  * a NULL pointer dereference flaw was found in the eCryptfs implementation
  in the Linux kernel. A local attacker could use this flaw to cause a local
  denial of service or escalate their privileges. (CVE-2009-2908, Important)

  * a flaw was found in the NFSv4 implementation. The kernel would do an
  unnecessary permission check after creating a file. This check would
  usually fail and leave the file with the permission bits set to random
  values. Note: This is a server-side only issue. (CVE-2009-3286, Important)

  * a NULL pointer dereference flaw was found in each of the following
  functions in the Linux kernel: pipe_read_open(), pipe_write_open(), and
  pipe_rdwr_open(). When the mutex lock is not held, the i_pipe pointer could
  be released by other processes before it is used to update the pipe's
  reader and writer counters. This could lead to a local denial of service or
  privilege escalation. (CVE-2009-3547, Important)

  * a flaw was found in the Realtek r8169 Ethernet driver in the Linux
  kernel. pci_unmap_single() presented a memory leak that could lead to IOMMU
  space exhaustion and a system crash. An attacker on the local network could
  abuse this flaw by using jumbo frames for large amounts of network traffic.
  (CVE-2009-3613, Important)

  * missing initialization flaws were found in the Linux kernel. Padding data
  in several core network structures was not initialized properly before
  being sent to user-space. These flaws could lead to information leaks.
  (CVE-2009-3228, Moderate)

  Bug fixes:

  * with network bonding in the 'balance-tlb' or 'balance-alb' mode, the
  primary setting for the primary slave device was lost when said device was
  brought down. Bringing the slave back up did not restore the primary
  setting. (BZ#517971)

  * some faulty serial device hardware caused systems running the kernel-xen
  kernel to take a very long time to boot. (BZ#524153)

  * a caching bug in nfs_readdir() may have caused NFS clients to see
  duplicate files or not see all files in a directory. (BZ#526960)

  * the RHSA-2009:1243 update removed the mpt_msi_enable option, preventing
  certain scripts from running. This update adds the o ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
