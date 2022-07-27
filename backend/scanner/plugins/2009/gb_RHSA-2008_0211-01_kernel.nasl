###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2008:0211-01
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
  
  * the absence of a protection mechanism when attempting to access a
  critical section of code has been found in the Linux kernel open file
  descriptors control mechanism, fcntl. This could allow a local unprivileged
  user to simultaneously execute code, which would otherwise be protected
  against parallel execution. As well, a race condition when handling locks
  in the Linux kernel fcntl functionality, may have allowed a process
  belonging to a local unprivileged user to gain re-ordered access to the
  descriptor table. (CVE-2008-1669, Important)
  
  * the absence of a protection mechanism when attempting to access a
  critical section of code, as well as a race condition, have been found in
  the Linux kernel file system event notifier, dnotify. This could allow a
  local unprivileged user to get inconsistent data, or to send arbitrary
  signals to arbitrary system processes. (CVE-2008-1375, Important)
  
  Red Hat would like to thank Nick Piggin for responsibly disclosing the
  following issue:
  
  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a kernel crash.
  (CVE-2008-0007, Important)
  
  * a flaw was found when performing asynchronous input or output operations
  on a FIFO special file. A local unprivileged user could use this flaw to
  cause a kernel panic. (CVE-2007-5001, Important)
  
  * a flaw was found in the way core dump files were created. If a local user
  could get a root-owned process to dump a core file into a directory, which
  the user has write access to, they could gain read access to that core
  file. This could potentially grant unauthorized access to sensitive
  information. (CVE-2007-6206, Moderate)
  
  * a buffer overflow was found in the Linux kernel ISDN subsystem. A local
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2007-6151, Moderate)
  
  * a race condition found in the mincore system core could allow a local
  user to cause a denial of service (system hang). (CVE-2006-4814, Moderate)
  
  * it was discovered that the Linux kernel handled string operations in the
  opposite way to the GNU Compiler Collection (GCC). This could allow a local
  un ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00000.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309207");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0211-01");
  script_cve_id("CVE-2006-4814", "CVE-2007-5001", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1669");
  script_name( "RedHat Update for kernel RHSA-2008:0211-01");

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

if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-BOOT", rpm:"kernel-BOOT~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-unsupported", rpm:"kernel-hugemem-unsupported~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-unsupported", rpm:"kernel-smp-unsupported~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-unsupported", rpm:"kernel-unsupported~2.4.21~57.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
