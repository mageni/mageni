###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2008:0885-01
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

  Security fixes:
  
  * a missing capability check was found in the Linux kernel do_change_type
  routine. This could allow a local unprivileged user to gain privileged
  access or cause a denial of service. (CVE-2008-2931, Important)
  
  * a flaw was found in the Linux kernel Direct-IO implementation. This could
  allow a local unprivileged user to cause a denial of service.
  (CVE-2007-6716, Important)
  
  * Tobias Klein reported a missing check in the Linux kernel Open Sound
  System (OSS) implementation. This deficiency could lead to a possible
  information leak. (CVE-2008-3272, Moderate)
  
  * a deficiency was found in the Linux kernel virtual filesystem (VFS)
  implementation. This could allow a local unprivileged user to attempt file
  creation within deleted directories, possibly causing a denial of service.
  (CVE-2008-3275, Moderate)
  
  * a flaw was found in the Linux kernel tmpfs implementation. This could
  allow a local unprivileged user to read sensitive information from the
  kernel. (CVE-2007-6417, Moderate)
  
  Bug fixes:
  
  * when copying a small IPoIB packet from the original skb it was received
  in to a new, smaller skb, all fields in the new skb were not initialized.
  This may have caused a kernel oops.
  
  * previously, data may have been written beyond the end of an array,
  causing memory corruption on certain systems, resulting in hypervisor
  crashes during context switching.
  
  * a kernel crash may have occurred on heavily-used Samba servers after 24
  to 48 hours of use.
  
  * under heavy memory pressure, pages may have been swapped out from under
  the SGI Altix XPMEM driver, causing silent data corruption in the kernel.
  
  * the ixgbe driver is untested, but support was advertised for the Intel
  82598 network card. If this card was present when the ixgbe driver was
  loaded, a NULL pointer dereference and a panic occurred.
  
  * on certain systems, if multiple InfiniBand queue pairs simultaneously
  fell into an error state, an overrun may have occurred, stopping traffic.
  
  * with bridging, when forward delay was set to zero, setting an interface
  to the forwarding state was delayed by one or possibly two timers,
  depending on whether STP was enabled. This may have caused long delays in
  moving an interface to the forwarding state. This issue caused packet loss
  when migrating virtual machines, preventing them from being migrated
  without interrupting applications.
  
  * on certain multinode systems, IPMI device nodes  ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-September/msg00013.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309552");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0885-01");
  script_cve_id("CVE-2008-2931", "CVE-2008-3275", "CVE-2007-6417", "CVE-2007-6716", "CVE-2008-3272");
  script_name( "RedHat Update for kernel RHSA-2008:0885-01");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.13.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
