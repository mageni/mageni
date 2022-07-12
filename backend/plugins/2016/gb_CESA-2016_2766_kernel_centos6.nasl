###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:2766 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882598");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-20 05:37:30 +0100 (Sun, 20 Nov 2016)");
  script_cve_id("CVE-2016-1583", "CVE-2016-2143");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:2766 centos6");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * It was found that stacking a file system over procfs in the Linux kernel
could lead to a kernel stack overflow due to deep nesting, as demonstrated
by mounting ecryptfs over procfs and creating a recursion by mapping
/proc/environ. An unprivileged, local user could potentially use this flaw
to escalate their privileges on the system. (CVE-2016-1583, Important)

  * It was reported that on s390x, the fork of a process with four page table
levels will cause memory corruption with a variety of symptoms. All
processes are created with three level page table and a limit of 4TB for
the address space. If the parent process has four page table levels with a
limit of 8PB, the function that duplicates the address space will try to
copy memory areas outside of the address space limit for the child process.
(CVE-2016-2143, Moderate)

Bug Fix(es):

  * Use of a multi-threaded workload with high memory mappings sometimes
caused a kernel panic, due to a race condition between the context switch
and the pagetable upgrade. This update fixes the switch_mm() by using the
complete asce parameter instead of the asce_bits parameter. As a result,
the kernel no longer panics in the described scenario. (BZ#1377472)

  * When iptables created the Transmission Control Protocol (TCP) reset
packet, a kernel crash could occur due to uninitialized pointer to the TCP
header within the Socket Buffer (SKB). This update fixes the transport
header pointer in TCP reset for both IPv4 and IPv6, and the kernel no
longer crashes in the described situation.(BZ#1372266)

  * Previously, when the Enhanced Error Handling (EEH) mechanism did not
block the PCI configuration space access and an error was detected, a
kernel panic occurred. This update fixes EEH to fix this problem. As a
result, the kernel no longer panics in the described scenario. (BZ#1379596)

  * When the lockd service failed to start up completely, the notifier blocks
were in some cases registered on a notification chain multiple times, which
caused the occurrence of a circular list on the notification chain.
Consequently, a soft lock-up or a kernel oops occurred. With this update,
the notifier blocks are unregistered if lockd fails to start up completely,
and the soft lock-ups or the kernel oopses no longer occur under the
described circumstances. (BZ#1375637)

  * When the Fibre Channel over Ethernet (FCoE) was configured, the FCoE
MaxFrameSize parameter was incorrectly restricted to 1452. With this
update, the NETIF_F_ALL_FCOE symbol
is no longer ignored, which fixes this bug.  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-November/022153.html");
  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~642.11.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
