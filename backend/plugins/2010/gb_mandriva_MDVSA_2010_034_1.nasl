###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDVSA-2010:034-1 (kernel)
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
tag_insight = "Some vulnerabilities were discovered and corrected in the Linux
  2.6 kernel:

  Array index error in the gdth_read_event function in
  drivers/scsi/gdth.c in the Linux kernel before 2.6.32-rc8 allows
  local users to cause a denial of service or possibly gain privileges
  via a negative event index in an IOCTL request. (CVE-2009-3080)
  
  The collect_rx_frame function in drivers/isdn/hisax/hfc_usb.c in the
  Linux kernel before 2.6.32-rc7 allows attackers to have an unspecified
  impact via a crafted HDLC packet that arrives over ISDN and triggers
  a buffer under-read. (CVE-2009-4005)
  
  Additionally, the Linux kernel was updated to the stable release
  2.6.27.45.
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate
  
  Update:
  
  The virtualbox DKMS modules was not provided with MDVSA-2010:034
  for the Enterprise 5 product. This advisory provides the missing
  virtualbox packages.";

tag_affected = "kernel on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-02/msg00038.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314041");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 13:38:15 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:034-1");
  script_cve_id("CVE-2009-3080", "CVE-2009-4005");
  script_name("Mandriva Update for kernel MDVSA-2010:034-1 (kernel)");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.27.45~desktop~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.27.45~desktop586~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.27.45~server~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-desktop586-latest", rpm:"vboxadd-kernel-desktop586-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-desktop-latest", rpm:"vboxadd-kernel-desktop-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-server-latest", rpm:"vboxadd-kernel-server-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.27.45~desktop~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.27.45~desktop586~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.27.45~server~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-desktop586-latest", rpm:"vboxvfs-kernel-desktop586-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-desktop-latest", rpm:"vboxvfs-kernel-desktop-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-server-latest", rpm:"vboxvfs-kernel-server-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.27.45~desktop~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.27.45~desktop586~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.27.45~server~1mnb~2.0.2~2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~2.0.2~1.20100217.2.1mdv2009.0", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
