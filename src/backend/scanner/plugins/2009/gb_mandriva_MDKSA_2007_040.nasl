###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:040 (kernel)
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

  The isdn_ppp_ccp_reset_alloc_state function in drivers/isdn/isdn_ppp.c
  in the Linux 2.4 kernel before 2.4.34-rc4, as well as the 2.6 kernel,
  does not call the init_timer function for the ISDN PPP CCP reset state
  timer, which has unknown attack vectors and results in a system crash.
  (CVE-2006-5749)
  
  The listxattr syscall can corrupt user space under certain
  circumstances. The problem seems to be related to signed/unsigned
  conversion during size promotion. (CVE-2006-5753)
  
  The ext3fs_dirhash function in Linux kernel 2.6.x allows local users to
  cause a denial of service (crash) via an ext3 stream with malformed
  data structures. (CVE-2006-6053)
  
  The mincore function in the Linux kernel before 2.4.33.6, as well as
  the 2.6 kernel, does not properly lock access to user space, which has
  unspecified impact and attack vectors, possibly related to a deadlock.
  (CVE-2006-4814)
  
  The provided packages are patched to fix these vulnerabilities.  All
  users are encouraged to upgrade to these updated kernels immediately
  and reboot to effect the fixes.
  
  In addition to these security fixes, other fixes have been included
  such as:
  
  - Add Ralink RT2571W/RT2671 WLAN USB support (rt73 module) - Fix
  sys_msync() to report -ENOMEM as before when an unmapped area falls
  within its range, and not to overshoot (LSB regression) - Avoid disk
  sector_t overflow for &gt;2TB ext3 filesystem - USB: workaround to fix HP
  scanners detection (#26728) - USB: unusual_devs.h for Sony floppy
  (#28378) - Add preliminary ICH9 support - Add TI sd card reader
  support - Add RT61 driver - KVM update - Fix bttv vbi offset
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-02/msg00009.php");
  script_oid("1.3.6.1.4.1.25623.1.0.306994");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:040");
  script_cve_id("CVE-2006-5749", "CVE-2006-5753", "CVE-2006-6053", "CVE-2006-4814");
  script_name( "Mandriva Update for kernel MDKSA-2007:040 (kernel)");

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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.10mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
