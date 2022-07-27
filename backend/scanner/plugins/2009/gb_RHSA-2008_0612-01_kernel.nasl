###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2008:0612-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:
  
  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)
  
  * a flaw was found in the Linux kernel setrlimit system call, when setting
  RLIMIT_CPU to a certain value. This could allow a local unprivileged user
  to bypass the CPU time limit. (CVE-2008-1294, Moderate)
  
  * multiple NULL pointer dereferences were found in various Linux kernel
  network drivers. These drivers were missing checks for terminal validity,
  which could allow privilege escalation. (CVE-2008-2812, Moderate)
  
  These updated packages fix the following bugs:
  
  * the GNU libc stub resolver is a minimal resolver that works with Domain
  Name System (DNS) servers to satisfy requests from applications for names.
  The GNU libc stub resolver did not specify a source UDP port, and therefore
  used predictable port numbers. This could have made DNS spoofing attacks
  easier.
  
  The Linux kernel has been updated to implement random UDP source ports
  where none are specified by an application. This allows applications, such
  as those using the GNU libc stub resolver, to use random UDP source ports,
  helping to make DNS spoofing attacks harder.
  
  * when using certain hardware, a bug in UART_BUG_TXEN may have caused
  incorrect hardware detection, causing data flow to &quot;/dev/ttyS1&quot; to hang.
  
  * a 50-75% drop in NFS server rewrite performance, compared to Red Hat
  Enterprise Linux 4.6, has been resolved.
  
  * due a bug in the fast userspace mutex code, while one thread fetched a
  pointer, another thread may have removed it, causing the first thread to
  fetch the wrong pointer, possibly causing a system crash.
  
  * on certain Hitachi hardware, removing the &quot;uhci_hcd&quot; module caused a
  kernel oops, and the following error:
  
  BUG: warning at arch/ia64/kernel/iosapic.c:1001/iosapic_unregister_intr()
  
  Even after the &quot;uhci_hcd&quot; module was reloaded, there was no access to USB
  devices. As well, on systems that have legacy interrupts,
  &quot;acpi_unregister_gsi&quot; incorrectly called &quot;iosapci_unregister_intr()&quot;,
  causing warning messages to be logged.
  
  * when a page was mapped with mmap(), and &quot;PROT_WRITE&quot; was the only
  &quot;prot&quot; argument, the first read of that page caused a segmentation fault.
  If ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-August/msg00000.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306718");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2008:0612-01");
  script_cve_id("CVE-2008-2136", "CVE-2008-1294", "CVE-2008-2812", "CVE-2008-2826");
  script_name( "RedHat Update for kernel RHSA-2008:0612-01");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.10.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
