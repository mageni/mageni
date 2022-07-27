###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2014:0740 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881954");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-06-17 10:04:18 +0530 (Tue, 17 Jun 2014)");
  script_cve_id("CVE-2013-7339", "CVE-2014-1737", "CVE-2014-1738");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2014:0740 centos5");

  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any
Linux operating system.

  * A flaw was found in the way the Linux kernel's floppy driver handled user
space provided data in certain error code paths while processing FDRAWCMD
IOCTL commands. A local user with write access to /dev/fdX could use this
flaw to free (using the kfree() function) arbitrary kernel memory.
(CVE-2014-1737, Important)

  * It was found that the Linux kernel's floppy driver leaked internal kernel
memory addresses to user space during the processing of the FDRAWCMD IOCTL
command. A local user with write access to /dev/fdX could use this flaw to
obtain information about the kernel heap arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two flaws
(CVE-2014-1737 in combination with CVE-2014-1738) to escalate their
privileges on the system.

  * A NULL pointer dereference flaw was found in the rds_ib_laddr_check()
function in the Linux kernel's implementation of Reliable Datagram Sockets
(RDS). A local, unprivileged user could use this flaw to crash the system.
(CVE-2013-7339, Moderate)

Red Hat would like to thank Matthew Daley for reporting CVE-2014-1737 and
CVE-2014-1738.

This update also fixes the following bugs:

  * A bug in the futex system call could result in an overflow when passing
a very large positive timeout. As a consequence, the FUTEX_WAIT operation
did not work as intended and the system call was timing out immediately.
A backported patch fixes this bug by limiting very large positive timeouts
to the maximal supported value. (BZ#1091832)

  * A new Linux Security Module (LSM) functionality related to the setrlimit
hooks should produce a warning message when used by a third party module
that could not cope with it. However, due to a programming error, the
kernel could print this warning message when a process was setting rlimits
for a different process, or if rlimits were modified by another than the
main thread even though there was no incompatible third party module. This
update fixes the relevant code and ensures that the kernel handles this
warning message correctly. (BZ#1092869)

  * Previously, the kernel was unable to detect KVM on system boot if the
Hyper-V emulation was enabled. A patch has been applied to ensure that
both KVM and Hyper-V hypervisors are now correctly detected during system
boot. (BZ#1094152)

  * A function in the RPC code responsible for verifying whether cached
credentials match the current process did not perform the check correctly.
The code checked only whether the groups in the current process
credentials appear in the same order as i ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020363.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.9.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
