###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0394-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  
  * RHSA-2009:1024 introduced a flaw in the ptrace implementation on Itanium
  systems. ptrace_check_attach() was not called during certain ptrace()
  requests. Under certain circumstances, a local, unprivileged user could use
  this flaw to call ptrace() on a process they do not own, giving them
  control over that process. (CVE-2010-0729, Important)
  
  * a flaw was found in the kernel's Unidirectional Lightweight Encapsulation
  (ULE) implementation. A remote attacker could send a specially-crafted ISO
  MPEG-2 Transport Stream (TS) frame to a target system, resulting in a
  denial of service. (CVE-2010-1086, Important)
  
  * a use-after-free flaw was found in tcp_rcv_state_process() in the
  kernel's TCP/IP protocol suite implementation. If a system using IPv6 had
  the IPV6_RECVPKTINFO option set on a listening socket, a remote attacker
  could send an IPv6 packet to that system, causing a kernel panic.
  (CVE-2010-1188, Important)
  
  * a divide-by-zero flaw was found in azx_position_ok() in the Intel High
  Definition Audio driver, snd-hda-intel. A local, unprivileged user could
  trigger this flaw to cause a denial of service. (CVE-2010-1085, Moderate)
  
  * an information leak flaw was found in the kernel's USB implementation.
  Certain USB errors could result in an uninitialized kernel buffer being
  sent to user-space. An attacker with physical access to a target system
  could use this flaw to cause an information leak. (CVE-2010-1083, Low)
  
  Red Hat would like to thank Ang Way Chuang for reporting CVE-2010-1086.
  
  Bug fixes:
  
  * a regression prevented the Broadcom BCM5761 network device from working
  when in the first (top) PCI-E slot of Hewlett-Packard (HP) Z600 systems.
  Note: The card worked in the 2nd or 3rd PCI-E slot. (BZ#567205)
  
  * the Xen hypervisor supports 168 GB of RAM for 32-bit guests. The physical
  address range was set incorrectly, however, causing 32-bit,
  para-virtualized Red Hat Enterprise Linux 4.8 guests to crash when launched
  on AMD64 or Intel 64 hosts that have more than 64 GB of RAM. (BZ#574392)
  
  * RHSA-2009:1024 introduced a regression, causing diskdump to fail on
  systems with certain adapters using the qla2xxx driver. (BZ#577234)
  
  * a race condition caused TX to stop in a guest using the virtio_net
  driver. (BZ#580089)
  
  * on some systems, using the &quot;arp_validate=3&quot; bonding option caused both
 ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-May/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314248");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:42:01 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2010:0394-01");
  script_cve_id("CVE-2010-0729", "CVE-2010-1083", "CVE-2010-1085", "CVE-2010-1086", "CVE-2010-1188");
  script_name("RedHat Update for kernel RHSA-2010:0394-01");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.0.25.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
