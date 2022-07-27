###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0146-01
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

  This update fixes the following security issues:
  
  * a NULL pointer dereference flaw was found in the sctp_rcv_ootb() function
  in the Linux kernel Stream Control Transmission Protocol (SCTP)
  implementation. A remote attacker could send a specially-crafted SCTP
  packet to a target system, resulting in a denial of service.
  (CVE-2010-0008, Important)
  
  * a NULL pointer dereference flaw was found in the Linux kernel. During a
  core dump, the kernel did not check if the Virtual Dynamically-linked
  Shared Object page was accessible. On Intel 64 and AMD64 systems, a local,
  unprivileged user could use this flaw to cause a kernel panic by running a
  crafted 32-bit application. (CVE-2009-4271, Important)
  
  * an information leak was found in the print_fatal_signal() implementation
  in the Linux kernel. When &quot;/proc/sys/kernel/print-fatal-signals&quot; is set to
  1 (the default value is 0), memory that is reachable by the kernel could be
  leaked to user-space. This issue could also result in a system crash. Note
  that this flaw only affected the i386 architecture. (CVE-2010-0003,
  Moderate)
  
  * on AMD64 systems, it was discovered that the kernel did not ensure the
  ELF interpreter was available before making a call to the SET_PERSONALITY
  macro. A local attacker could use this flaw to cause a denial of service by
  running a 32-bit application that attempts to execute a 64-bit application.
  (CVE-2010-0307, Moderate)
  
  * missing capability checks were found in the ebtables implementation, used
  for creating an Ethernet bridge firewall. This could allow a local,
  unprivileged user to bypass intended capability restrictions and modify
  ebtables rules. (CVE-2010-0007, Low)
  
  This update also fixes the following bugs:
  
  * under some circumstances, a locking bug could have caused an online ext3
  file system resize to deadlock, which may have, in turn, caused the file
  system or the entire system to become unresponsive. In either case, a
  reboot was required after the deadlock. With this update, using resize2fs
  to perform an online resize of an ext3 file system works as expected.
  (BZ#553135)
  
  * some ATA and SCSI devices were not honoring the barrier=1 mount option,
  which could result in data loss after a crash or power loss. This update
  applies a patch to the Linux SCSI driver to ensure ordered write caching.
  This solution does not provide cache flus ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00012.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314445");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0146-01");
  script_cve_id("CVE-2009-4271", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0307", "CVE-2009-4538");
  script_name("RedHat Update for kernel RHSA-2010:0146-01");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.0.23.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
