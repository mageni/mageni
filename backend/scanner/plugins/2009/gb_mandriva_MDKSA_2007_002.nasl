###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:002 (kernel)
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

  The Linux kernel does not properly save or restore EFLAGS during a
  context switch, or reset the flags when creating new threads, which
  could allow a local user to cause a Denial of Service (process crash)
  (CVE-2006-5173).
  
  The seqfile handling in the 2.6 kernel up to 2.6.18 allows local users
  to cause a DoS (hang or oops) via unspecified manipulations that
  trigger an infinite loop while searching for flowlabels
  (CVE-2006-5619).
  
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
  
  - added the marvell IDE driver - use a specific driver Jmicron chipsets
  rather than using a generic one - updated the sky2 driver to fix some
  network hang issues
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-01/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308107");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDKSA", value: "2007:002");
  script_cve_id("CVE-2006-5173", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-6106");
  script_name( "Mandriva Update for kernel MDKSA-2007:002 (kernel)");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.8mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince", rpm:"evince~0.6.0~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
