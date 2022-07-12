###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:0014 centos4 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-January/015556.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880928");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-3275", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025",
                "CVE-2008-5029", "CVE-2008-5300", "CVE-2008-5702");
  script_name("CentOS Update for kernel CESA-2009:0014 centos4 i386");

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

  This update addresses the following security issues:

  * the sendmsg() function in the Linux kernel did not block during UNIX
  socket garbage collection. This could, potentially, lead to a local denial
  of service. (CVE-2008-5300, Important)

  * when fput() was called to close a socket, the __scm_destroy() function in
  the Linux kernel could make indirect recursive calls to itself. This could,
  potentially, lead to a local denial of service. (CVE-2008-5029, Important)

  * a deficiency was found in the Linux kernel virtual file system (VFS)
  implementation. This could allow a local, unprivileged user to make a
  series of file creations within deleted directories, possibly causing a
  denial of service. (CVE-2008-3275, Moderate)

  * a buffer underflow flaw was found in the Linux kernel IB700 SBC watchdog
  timer driver. This deficiency could lead to a possible information leak. By
  default, the '/dev/watchdog' device is accessible only to the root user.
  (CVE-2008-5702, Low)

  * the hfs and hfsplus file systems code failed to properly handle corrupted
  data structures. This could, potentially, lead to a local denial of
  service. (CVE-2008-4933, CVE-2008-5025, Low)

  * a flaw was found in the hfsplus file system implementation. This could,
  potentially, lead to a local denial of service when write operations were
  performed. (CVE-2008-4934, Low)

  This update also fixes the following bugs:

  * when running Red Hat Enterprise Linux 4.6 and 4.7 on some systems running
  Intel® CPUs, the cpuspeed daemon did not run, preventing the CPU speed from
  being changed, such as not being reduced to an idle state when not in use.

  * mmap() could be used to gain access to beyond the first megabyte of RAM,
  due to insufficient checks in the Linux kernel code. Checks have been added
  to prevent this.

  * attempting to turn keyboard LEDs on and off rapidly on keyboards with
  slow keyboard controllers, may have caused key presses to fail.

  * after migrating a hypervisor guest, the MAC address table was not
  updated, causing packet loss and preventing network connections to the
  guest. Now, a gratuitous ARP request is sent after migration. This
  refreshes the ARP caches, minimizing network downtime.

  * writing crash dumps with diskdump may have caused a kernel panic on
  Non-Uniform Memory Access (NUMA) systems with certain memory
  configurations.

  * on big-endian systems, such as PowerPC, the getsockopt() function
  incorrectly returned 0 depending on  ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~78.0.13.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
