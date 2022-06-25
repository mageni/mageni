###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:012 (kernel)
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
tag_insight = "Some vulnerabilities were discovered and corrected in the Linux 2.6
  kernel:

  The __block_prepate_write function in the 2.6 kernel before 2.6.13 does
  not properly clear buffers during certain error conditions, which
  allows users to read portions of files that have been unlinked
  (CVE-2006-4813).
  
  The clip_mkip function of the ATM subsystem in the 2.6 kernel allows
  remote attackers to dause a DoS (panic) via unknown vectors that cause
  the ATM subsystem to access the memory of socket buffers after they are
  freed (CVE-2006-4997).
  
  The NFS lockd in the 2.6 kernel before 2.6.16 allows remote attackers
  to cause a DoS (process crash) and deny access to NFS exports via
  unspecified vectors that trigger a kernel oops and a deadlock
  (CVE-2006-5158).
  
  The seqfile handling in the 2.6 kernel up to 2.6.18 allows local users
  to cause a DoS (hang or oops) via unspecified manipulations that
  trigger an infinite loop while searching for flowlabels
  (CVE-2006-5619).
  
  A missing call to init_timer() in the isdn_ppp code of the Linux kernel
  can allow remote attackers to send a special kind of PPP pakcet which
  may trigger a kernel oops (CVE-2006-5749).
  
  An integer overflow in the 2.6 kernel prior to 2.6.18.4 could allow a
  local user to execute arbitrary code via a large maxnum value in an
  ioctl request (CVE-2006-5751).
  
  A race condition in the ISO9660 filesystem handling could allow a local
  user to cause a DoS (infinite loop) by mounting a crafted ISO9660
  filesystem containing malformed data structures (CVE-2006-5757).
  
  A vulnerability in the bluetooth support could allow for overwriting
  internal CMTP and CAPI data structures via malformed packets
  (CVE-2006-6106).
  
  The provided packages are patched to fix these vulnerabilities.  All
  users are encouraged to upgrade to these updated kernels immediately
  and reboot to effect the fixes.
  
  In addition to these security fixes, other fixes have been included
  such as:
  
  - __bread oops fix
  
  - added e1000_ng (nineveh support)
  
  - added sata_svw (Broadcom SATA support)
  
  - added Marvell PATA chipset support
  
  - disabled mmconf on some broken hardware/BIOSes
  
  - use GENERICARCH and enable bigsmp apic model for tulsa machines
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-01/msg00018.php");
  script_oid("1.3.6.1.4.1.25623.1.0.306953");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDKSA", value: "2007:012");
  script_cve_id("CVE-2006-4813", "CVE-2006-4997", "CVE-2006-5158", "CVE-2006-5619", "CVE-2006-5749", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-6106");
  script_name( "Mandriva Update for kernel MDKSA-2007:012 (kernel)");

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

if(release == "MNDK_2006.0")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-BOOT", rpm:"kernel-BOOT~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-i586-up-1GB", rpm:"kernel-i586-up-1GB~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-i686-up-4GB", rpm:"kernel-i686-up-4GB~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xbox", rpm:"kernel-xbox~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.12.29mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
