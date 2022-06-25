###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDVSA-2008:105 (kernel)
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
tag_insight = "The CIFS filesystem in the Linux kernel before 2.6.22, when Unix
  extension support is enabled, does not honor the umask of a process,
  which allows local users to gain privileges. (CVE-2007-3740)

  The drm/i915 component in the Linux kernel before 2.6.22.2, when
  used with i965G and later chipsets, allows local users with access
  to an X11 session and Direct Rendering Manager (DRM) to write
  to arbitrary memory locations and gain privileges via a crafted
  batchbuffer. (CVE-2007-3851)
  
  The (1) hugetlb_vmtruncate_list and (2) hugetlb_vmtruncate functions
  in fs/hugetlbfs/inode.c in the Linux kernel before 2.6.19-rc4 perform
  certain prio_tree calculations using HPAGE_SIZE instead of PAGE_SIZE
  units, which allows local users to cause a denial of service (panic)
  via unspecified vectors. (CVE-2007-4133)
  
  The IA32 system call emulation functionality in Linux kernel 2.4.x
  and 2.6.x before 2.6.22.7, when running on the x86_64 architecture,
  does not zero extend the eax register after the 32bit entry path to
  ptrace is used, which might allow local users to gain privileges by
  triggering an out-of-bounds access to the system call table using
  the %RAX register. This vulnerability is now being fixed in the Xen
  kernel too. (CVE-2007-4573)
  
  Integer underflow in the ieee80211_rx function in
  net/ieee80211/ieee80211_rx.c in the Linux kernel 2.6.x before
  2.6.23 allows remote attackers to cause a denial of service (crash)
  via a crafted SKB length value in a runt IEEE 802.11 frame when
  the IEEE80211_STYPE_QOS_DATA flag is set, aka an off-by-two
  error. (CVE-2007-4997)
  
  The disconnect method in the Philips USB Webcam (pwc) driver in Linux
  kernel 2.6.x before 2.6.22.6 relies on user space to close the device,
  which allows user-assisted local attackers to cause a denial of service
  (USB subsystem hang and CPU consumption in khubd) by not closing the
  device after the disconnect is invoked. NOTE: this rarely crosses
  privilege boundaries, unless the attacker can convince the victim to
  unplug the affected device. (CVE-2007-5093)
  
  A race condition in the directory notification subsystem (dnotify)
  in Linux kernel 2.6.x before 2.6.24.6, and 2.6.25 before 2.6.25.1,
  allows local users to cause a denial of service (OOPS) and possibly
  gain privileges via unspecified vectors. (CVE-2008-1375)
  
  The Linux kernel before 2.6.25.2 does not apply a certain protection
  mechanism for fcntl functionality, which allows local users to (1)
  execute code in parallel or (2) exploit a race condition to obtain
  re-ordered access to the descriptor table. (CVE-2008-1669)
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-05/msg00027.php");
  script_oid("1.3.6.1.4.1.25623.1.0.307437");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:105");
  script_cve_id("CVE-2007-3740", "CVE-2007-3851", "CVE-2007-4133", "CVE-2007-4573", "CVE-2007-4997", "CVE-2007-5093", "CVE-2008-1375", "CVE-2008-1669");
  script_name( "Mandriva Update for kernel MDVSA-2008:105 (kernel)");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc-latest", rpm:"kernel-doc-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise-latest", rpm:"kernel-enterprise-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-latest", rpm:"kernel-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy-latest", rpm:"kernel-legacy-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped-latest", rpm:"kernel-source-stripped-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0-latest", rpm:"kernel-xen0-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.18mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-latest", rpm:"kernel-xenU-latest~2.6.17~18mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
