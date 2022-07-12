###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:078 (kernel)
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

  When SELinux hooks are enabled, the kernel could allow a local user
  to cause a DoS (crash) via a malformed file stream that triggers a
  NULL pointer derefernece (CVE-2006-6056).
  
  Multiple buffer overflows in the (1) read and (2) write handlers in
  the Omnikey CardMan 4040 driver in the Linux kernel before 2.6.21-rc3
  allow local users to gain privileges. (CVE-2007-0005)
  
  The Linux kernel version 2.6.13 to 2.6.20.1 allowed a remote attacker to
  cause a DoS (oops) via a crafted NFSACL2 ACCESS request that triggered
  a free of an incorrect pointer (CVE-2007-0772).
  
  A local user could read unreadable binaries by using the interpreter
  (PT_INTERP) functionality and triggering a core dump; a variant of
  CVE-2004-1073 (CVE-2007-0958).
  
  The ipv6_getsockopt_sticky function in net/ipv6/ipv6_sockglue.c in the
  Linux kernel before 2.6.20.2 allows local users to read arbitrary
  kernel memory via certain getsockopt calls that trigger a NULL
  dereference. (CVE-2007-1000)
  
  Buffer overflow in the bufprint function in capiutil.c in libcapi,
  as used in Linux kernel 2.6.9 to 2.6.20 and isdn4k-utils, allows local
  users to cause a denial of service (crash) and possibly gain privileges
  via a crafted CAPI packet. (CVE-2007-1217)
  
  The do_ipv6_setsockopt function in net/ipv6/ipv6_sockglue.c in Linux
  kernel 2.6.17, and possibly other versions, allows local users to cause
  a denial of service (oops) by calling setsockopt with the IPV6_RTHDR
  option name and possibly a zero option length or invalid option value,
  which triggers a NULL pointer dereference. (CVE-2007-1388)
  
  net/ipv6/tcp_ipv6.c in Linux kernel 2.4 and 2.6.x up to 2.6.21-rc3
  inadvertently copies the ipv6_fl_socklist from a listening TCP socket
  to child sockets, which allows local users to cause a denial of service
  (OOPS) or double-free by opening a listeing IPv6 socket, attaching a
  flow label, and connecting to that socket. (CVE-2007-1592)
  
  The provided packages are patched to fix these vulnerabilities.
  All users are encouraged to upgrade to these updated kernels immediately
  and reboot to effect the fixes.
  
  In addition to these security fixes, other fixes have been included
  such as:
  
  - Suspend to disk speed improvements
  - Add nmi watchdog support for core2
  - Add atl1 driver
  - Update KVM
  - Add acer_acpi
  - Update asus_acpi
  - Fix suspend on r8169, i8259A
  - Fix suspend when using ondemand governor
  - Add ide acpi support
  - Add suspend/resume support ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-04/msg00006.php");
  script_oid("1.3.6.1.4.1.25623.1.0.307518");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "MDKSA", value: "2007:078");
  script_cve_id("CVE-2006-6056", "CVE-2007-0005", "CVE-2007-0772", "CVE-2004-1073", "CVE-2007-0958", "CVE-2007-1000", "CVE-2007-1217", "CVE-2007-1388", "CVE-2007-1592");
  script_name( "Mandriva Update for kernel MDKSA-2007:078 (kernel)");

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.13mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
