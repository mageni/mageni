###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0779-01
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
  
  * Information leak flaws were found in the Linux kernel Traffic Control
  Unit implementation. A local attacker could use these flaws to cause the
  kernel to leak kernel memory to user-space, possibly leading to the
  disclosure of sensitive information. (CVE-2010-2942, Moderate)
  
  * A flaw was found in the tcf_act_police_dump() function in the Linux
  kernel network traffic policing implementation. A data structure in
  tcf_act_police_dump() was not initialized properly before being copied to
  user-space. A local, unprivileged user could use this flaw to cause an
  information leak. (CVE-2010-3477, Moderate)
  
  * A missing upper bound integer check was found in the sys_io_submit()
  function in the Linux kernel asynchronous I/O implementation. A local,
  unprivileged user could use this flaw to cause an information leak.
  (CVE-2010-3067, Low)
  
  Red Hat would like to thank Tavis Ormandy for reporting CVE-2010-3067.
  
  This update also fixes the following bugs:
  
  * When two systems using bonding devices in the adaptive load balancing
  (ALB) mode communicated with each other, an endless loop of ARP replies
  started between these two systems due to a faulty MAC address update. With
  this update, the MAC address update no longer creates unneeded ARP replies.
  (BZ#629239)
  
  * When running the Connectathon NFS Testsuite with certain clients and Red
  Hat Enterprise Linux 4.8 as the server, nfsvers4, lock, and test2 failed
  the Connectathon test. (BZ#625535)
  
  * For UDP/UNIX domain sockets, due to insufficient memory barriers in the
  network code, a process sleeping in select() may have missed notifications
  about new data. In rare cases, this bug may have caused a process to sleep
  forever. (BZ#640117)
  
  * In certain situations, a bug found in either the HTB or TBF network
  packet schedulers in the Linux kernel could have caused a kernel panic when
  using Broadcom network cards with the bnx2 driver. (BZ#624363)
  
  * Previously, allocating fallback cqr for DASD reserve/release IOCTLs
  failed because it used the memory pool of the respective device. This
  update preallocates sufficient memory for a single reserve/release request.
  (BZ#626828)
  
  * In some situations a bug prevented &quot;force online&quot; succeeding for a DASD
  device. (BZ#626827)
  
  * Using the &quot;fsstress&quot; utility may have cause ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-October/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313072");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2010:0779-01");
  script_cve_id("CVE-2010-2942", "CVE-2010-3067", "CVE-2010-3477");
  script_name("RedHat Update for kernel RHSA-2010:0779-01");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp", rpm:"kernel-largesmp~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-largesmp-devel", rpm:"kernel-largesmp-devel~2.6.9~89.31.1.EL", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
