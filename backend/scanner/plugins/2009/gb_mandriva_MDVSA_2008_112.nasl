###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDVSA-2008:112 (kernel)
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
tag_insight = "Some vulnerabilities were discovered and corrected in the Linux
  2.6 kernel:

  The Datagram Congestion Control Protocol (DCCP) subsystem in the
  Linux kernel 2.6.18, and probably other versions, does not properly
  check feature lengths, which might allow remote attackers to execute
  arbitrary code, related to an unspecified overflow. (CVE-2008-2358)
  
  VFS in the Linux kernel before 2.6.22.16, and 2.6.23.x before
  2.6.23.14, performs tests of access mode by using the flag variable
  instead of the acc_mode variable, which might allow local users to
  bypass intended permissions and remove directories. (CVE-2008-0001)
  
  Linux kernel before 2.6.22.17, when using certain drivers that register
  a fault handler that does not perform range checks, allows local users
  to access kernel memory via an out-of-range offset. (CVE-2008-0007)
  
  Integer overflow in the hrtimer_start function in kernel/hrtimer.c
  in the Linux kernel before 2.6.23.10 allows local users to execute
  arbitrary code or cause a denial of service (panic) via a large
  relative timeout value. NOTE: some of these details are obtained from
  third party information. (CVE-2007-5966)
  
  The shmem_getpage function (mm/shmem.c) in Linux kernel 2.6.11
  through 2.6.23 does not properly clear allocated memory in some
  rare circumstances related to tmpfs, which might allow local
  users to read sensitive kernel data or cause a denial of service
  (crash). (CVE-2007-6417)
  
  The isdn_ioctl function in isdn_common.c in Linux kernel 2.6.23
  allows local users to cause a denial of service via a crafted ioctl
  struct in which iocts is not null terminated, which triggers a buffer
  overflow. (CVE-2007-6151)
  
  The do_coredump function in fs/exec.c in Linux kernel 2.4.x and 2.6.x
  up to 2.6.24-rc3, and possibly other versions, does not change the
  UID of a core dump file if it exists before a root process creates
  a core dump in the same location, which might allow local users to
  obtain sensitive information. (CVE-2007-6206)
  
  Buffer overflow in the isdn_net_setcfg function in isdn_net.c in
  Linux kernel 2.6.23 allows local users to have an unknown impact via
  a crafted argument to the isdn_ioctl function. (CVE-2007-6063)
  
  The wait_task_stopped function in the Linux kernel before 2.6.23.8
  checks a TASK_TRACED bit instead of an exit_state value, which
  allows local users to cause a denial of service (machine crash) via
  unspecified vectors. NOTE: some of these details are obtained from
  third party information. (CVE-2007-5500)
  
  The minix filesystem code in Lin ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-06/msg00018.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311263");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:112");
  script_cve_id("CVE-2008-2358", "CVE-2008-0001", "CVE-2008-0007", "CVE-2007-5966", "CVE-2007-6417", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6063", "CVE-2007-5500", "CVE-2006-6058");
  script_name( "Mandriva Update for kernel MDVSA-2008:112 (kernel)");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc-latest", rpm:"kernel-doc-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise-latest", rpm:"kernel-enterprise-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-latest", rpm:"kernel-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy-latest", rpm:"kernel-legacy-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped-latest", rpm:"kernel-source-stripped-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0-latest", rpm:"kernel-xen0-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.19mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-latest", rpm:"kernel-xenU-latest~2.6.17~19mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
