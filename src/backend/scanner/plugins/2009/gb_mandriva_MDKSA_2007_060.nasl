###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:060 (kernel)
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

  The 2.6.17 kernel and earlier, when running on IA64 and SPARC platforms
  would allow a local user to cause a DoS (crash) via a malformed ELF file
  (CVE-2006-4538).
  
  The mincore function in the Linux kernel did not properly lock access to
  user space, which has unspecified impact and attack vectors, possibly
  related to a deadlock (CVE-2006-4814).
  
  An unspecified vulnerability in the listxattr system call, when a &quot;bad
  inode&quot; is present, could allow a local user to cause a DoS (data
  corruption) and possibly gain privileges via unknown vectors
  (CVE-2006-5753).
  
  The zlib_inflate function allows local users to cause a crash via a
  malformed filesystem that uses zlib compression that triggers memory
  corruption (CVE-2006-5823).
  
  The ext3fs_dirhash function could allow local users to cause a DoS
  (crash) via an ext3 stream with malformed data structures
  (CVE-2006-6053).
  
  When SELinux hooks are enabled, the kernel could allow a local user to
  cause a DoS (crash) via a malformed file stream that triggers a NULL
  pointer derefernece (CVE-2006-6056).
  
  The key serial number collision avoidance code in the key_alloc_serial
  function in kernels 2.6.9 up to 2.6.20 allows local users to cause a
  crash via vectors thatr trigger a null dereference (CVE-2007-0006).
  
  The Linux kernel version 2.6.13 to 2.6.20.1 allowed a remote attacker
  to cause a DoS (oops) via a crafted NFSACL2 ACCESS request that
  triggered a free of an incorrect pointer (CVE-2007-0772).
  
  A local user could read unreadable binaries by using the interpreter
  (PT_INTERP) functionality and triggering a core dump; a variant of
  CVE-2004-1073 (CVE-2007-0958).
  
  The provided packages are patched to fix these vulnerabilities.  All
  users are encouraged to upgrade to these updated kernels immediately
  and reboot to effect the fixes.
  
  In addition to these security fixes, other fixes have been included
  such as:
  
  - add PCI IDs for cciss driver (HP ML370G5 / DL360G5)
  - fixed a mssive SCSI reset on megasas (Dell PE2960)
  - increased port-reset completion delay for HP controllers (HP ML350)
  - NUMA rnage fixes for x86_64
  - various netfilter fixes
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-03/msg00013.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309711");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "MDKSA", value: "2007:060");
  script_cve_id("CVE-2006-4538", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2007-0006", "CVE-2007-0772", "CVE-2004-1073", "CVE-2007-0958");
  script_name( "Mandriva Update for kernel MDKSA-2007:060 (kernel)");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-BOOT", rpm:"kernel-BOOT~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-i586-up-1GB", rpm:"kernel-i586-up-1GB~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-i686-up-4GB", rpm:"kernel-i686-up-4GB~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xbox", rpm:"kernel-xbox~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.12.31mdk~1~1mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
