###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1438 centos4 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016165.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880935");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1883", "CVE-2009-1895", "CVE-2009-2847", "CVE-2009-2848");
  script_name("CentOS Update for kernel CESA-2009:1438 centos4 i386");

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

  This update fixes the following security issues:

  * the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared when a
  setuid or setgid program was executed. A local, unprivileged user could use
  this flaw to bypass the mmap_min_addr protection mechanism and perform a
  NULL pointer dereference attack, or bypass the Address Space Layout
  Randomization (ASLR) security feature. (CVE-2009-1895, Important)

  * it was discovered that, when executing a new process, the clear_child_tid
  pointer in the Linux kernel is not cleared. If this pointer points to a
  writable portion of the memory of the new program, the kernel could corrupt
  four bytes of memory, possibly leading to a local denial of service or
  privilege escalation. (CVE-2009-2848, Important)

  * Solar Designer reported a missing capability check in the z90crypt driver
  in the Linux kernel. This missing check could allow a local user with an
  effective user ID (euid) of 0 to bypass intended capability restrictions.
  (CVE-2009-1883, Moderate)

  * a flaw was found in the way the do_sigaltstack() function in the Linux
  kernel copies the stack_t structure to user-space. On 64-bit machines, this
  flaw could lead to a four-byte information leak. (CVE-2009-2847, Moderate)

  This update also fixes the following bugs:

  * the gcc flag '-fno-delete-null-pointer-checks' was added to the kernel
  build options. This prevents gcc from optimizing out NULL pointer checks
  after the first use of a pointer. NULL pointer bugs are often exploited by
  attackers. Keeping these checks is a safety measure. (BZ#517964)

  * the Emulex LPFC driver has been updated to version 8.0.16.47, which
  fixes a memory leak that caused memory allocation failures and system
  hangs. (BZ#513192)

  * an error in the MPT Fusion driver makefile caused CSMI ioctls to not
  work with Serial Attached SCSI devices. (BZ#516184)

  * this update adds the mmap_min_addr tunable and restriction checks to help
  prevent unprivileged users from creating new memory mappings below the
  minimum address. This can help prevent the exploitation of NULL pointer
  deference bugs. Note that mmap_min_addr is set to zero (disabled) by
  default for backwards compatibility. (BZ#517904)

  * time-outs resulted in I/O errors being logged to '/var/log/messages' when
  running 'mt erase' on tape drives using certain LSI MegaRAID SAS adapters,
  preventing the command from completing. The megaraid_sas driver's timeout
  value is now set to t ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.11.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
