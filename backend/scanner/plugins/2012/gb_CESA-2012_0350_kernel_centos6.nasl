###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2012:0350 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-March/018468.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881118");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:12:12 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347",
                "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038",
                "CVE-2012-0045", "CVE-2012-0207");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2012:0350 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A buffer overflow flaw was found in the way the Linux kernel's XFS file
  system implementation handled links with overly long path names. A local,
  unprivileged user could use this flaw to cause a denial of service or
  escalate their privileges by mounting a specially-crafted disk.
  (CVE-2011-4077, Moderate)

  * Flaws in ghash_update() and ghash_final() could allow a local,
  unprivileged user to cause a denial of service. (CVE-2011-4081, Moderate)

  * A flaw was found in the Linux kernel's Journaling Block Device (JBD). A
  local, unprivileged user could use this flaw to crash the system by
  mounting a specially-crafted ext3 or ext4 disk. (CVE-2011-4132, Moderate)

  * It was found that the kvm_vm_ioctl_assign_device() function in the KVM
  (Kernel-based Virtual Machine) subsystem of a Linux kernel did not check if
  the user requesting device assignment was privileged or not. A local,
  unprivileged user on the host could assign unused PCI devices, or even
  devices that were in use and whose resources were not properly claimed by
  the respective drivers, which could result in the host crashing.
  (CVE-2011-4347, Moderate)

  * Two flaws were found in the way the Linux kernel's __sys_sendmsg()
  function, when invoked via the sendmmsg() system call, accessed user-space
  memory. A local, unprivileged user could use these flaws to cause a denial
  of service. (CVE-2011-4594, Moderate)

  * The RHSA-2011:1530 kernel update introduced an integer overflow flaw in
  the Linux kernel. On PowerPC systems, a local, unprivileged user could use
  this flaw to cause a denial of service. (CVE-2011-4611, Moderate)

  * A flaw was found in the way the KVM subsystem of a Linux kernel handled
  PIT (Programmable Interval Timer) IRQs (interrupt requests) when there was
  no virtual interrupt controller set up. A local, unprivileged user on the
  host could force this situation to occur, resulting in the host crashing.
  (CVE-2011-4622, Moderate)

  * A flaw was found in the way the Linux kernel's XFS file system
  implementation handled on-disk Access Control Lists (ACLs). A local,
  unprivileged user could use this flaw to cause a denial of service or
  escalate their privileges by mounting a specially-crafted disk.
  (CVE-2012-0038, Moderate)

  * A flaw was found in the way the Linux kernel's KVM hypervisor
  implementation emulated the syscall instruction for 32-bit guests. An
  unprivileged guest user could trigger this flaw to crash t ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.7.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
