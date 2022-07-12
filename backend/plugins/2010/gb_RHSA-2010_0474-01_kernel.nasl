###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0474-01
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
  
  * a NULL pointer dereference flaw was found in the Linux kernel NFSv4
  implementation. Several of the NFSv4 file locking functions failed to check
  whether a file had been opened on the server before performing locking
  operations on it. A local, unprivileged user on a system with an NFSv4
  share mounted could possibly use this flaw to cause a kernel panic (denial
  of service) or escalate their privileges. (CVE-2009-3726, Important)
  
  * a flaw was found in the sctp_process_unk_param() function in the Linux
  kernel Stream Control Transmission Protocol (SCTP) implementation. A remote
  attacker could send a specially-crafted SCTP packet to an SCTP listening
  port on a target system, causing a kernel panic (denial of service).
  (CVE-2010-1173, Important)
  
  * a race condition between finding a keyring by name and destroying a freed
  keyring was found in the Linux kernel key management facility. A local,
  unprivileged user could use this flaw to cause a kernel panic (denial of
  service) or escalate their privileges. (CVE-2010-1437, Important)
  
  Red Hat would like to thank Simon Vallet for responsibly reporting
  CVE-2009-3726; and Jukka Taimisto and Olli Jarva of Codenomicon Ltd, Nokia
  Siemens Networks, and Wind River on behalf of their customer, for
  responsibly reporting CVE-2010-1173.
  
  Bug fixes:
  
  * RHBA-2007:0791 introduced a regression in the Journaling Block Device
  (JBD). Under certain circumstances, removing a large file (such as 300 MB
  or more) did not result in inactive memory being freed, leading to the
  system having a large amount of inactive memory. Now, the memory is
  correctly freed. (BZ#589155)
  
  * the timer_interrupt() routine did not scale lost real ticks to logical
  ticks correctly, possibly causing time drift for 64-bit Red Hat Enterprise
  Linux 4 KVM (Kernel-based Virtual Machine) guests that were booted with the
  &quot;divider=x&quot; kernel parameter set to a value greater than 1. &quot;warning: many
  lost ticks&quot; messages may have been logged on the affected guest systems.
  (BZ#590551)
  
  * a bug could have prevented NFSv3 clients from having the most up-to-date
  file attributes for files on a given NFSv3 file system. In cases where a
  file type changed, such as if a file was removed and replaced with a
  directory of the same name, the NFSv3 client may not have noticed this
  change until stat(2) was ca ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-June/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313261");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-18 17:26:33 +0200 (Fri, 18 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2010:0474-01");
  script_cve_id("CVE-2009-3726", "CVE-2010-1173", "CVE-2010-1437");
  script_name("RedHat Update for kernel RHSA-2010:0474-01");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.0.26.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
