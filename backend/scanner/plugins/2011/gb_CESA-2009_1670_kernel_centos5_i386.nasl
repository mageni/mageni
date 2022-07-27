###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1670 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-December/016374.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880828");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");
  script_name("CentOS Update for kernel CESA-2009:1670 centos5 i386");

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

  * NULL pointer dereference flaws in the r128 driver. Checks to test if the
  Concurrent Command Engine state was initialized were missing in private
  IOCTL functions. An attacker could use these flaws to cause a local denial
  of service or escalate their privileges. (CVE-2009-3620, Important)

  * a NULL pointer dereference flaw in the NFSv4 implementation. Several
  NFSv4 file locking functions failed to check whether a file had been opened
  on the server before performing locking operations on it. A local user on a
  system with an NFSv4 share mounted could possibly use this flaw to cause a
  denial of service or escalate their privileges. (CVE-2009-3726, Important)

  * a flaw in tcf_fill_node(). A certain data structure in this function was
  not initialized properly before being copied to user-space. This could lead
  to an information leak. (CVE-2009-3612, Moderate)

  * unix_stream_connect() did not check if a UNIX domain socket was in the
  shutdown state. This could lead to a deadlock. A local, unprivileged user
  could use this flaw to cause a denial of service. (CVE-2009-3621, Moderate)

  Knowledgebase DOC-20536 has steps to mitigate NULL pointer dereference
  flaws.

  Bug fixes:

  * frequently changing a CPU between online and offline caused a kernel
  panic on some systems. (BZ#545583)

  * for the LSI Logic LSI53C1030 Ultra320 SCSI controller, read commands sent
  could receive incorrect data, preventing correct data transfer. (BZ#529308)

  * pciehp could not detect PCI Express hot plug slots on some systems.
  (BZ#530383)

  * soft lockups: inotify race and contention on dcache_lock. (BZ#533822,
  BZ#537019)

  * priority ordered lists are now used for threads waiting for a given
  mutex. (BZ#533858)

  * a deadlock in DLM could cause GFS2 file systems to lock up. (BZ#533859)

  * use-after-free bug in the audit subsystem crashed certain systems when
  running usermod. (BZ#533861)

  * on certain hardware configurations, a kernel panic when the Broadcom
  iSCSI offload driver (bnx2i.ko and cnic.ko) was loaded. (BZ#537014)

  * qla2xxx: Enabled MSI-X, and correctly handle the module parameter to
  control it. This improves performance for certain systems. (BZ#537020)

  * system crash when reading the cpuaffinity file on a system. (BZ#537346)

  * suspend-resume problems on systems with lots of logical CPUs, e.g. BX-EX.
  (BZ#539674)

  * off-by-one error in the legacy PCI bus check. (BZ#539675)

  * TSC was not made available  ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
