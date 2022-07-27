###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for xorg-x11 MDKSA-2007:079-1 (xorg-x11)
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
tag_insight = "Local exploitation of a memory corruption vulnerability in the X.Org
  and XFree86 X server could allow an attacker to execute arbitrary
  code with privileges of the X server, typically root.

  The vulnerability exists in the ProcXCMiscGetXIDList() function in the
  XC-MISC extension. This request is used to determine what resource IDs
  are available for use. This function contains two vulnerabilities,
  both result in memory corruption of either the stack or heap. The
  ALLOCATE_LOCAL() macro used by this function allocates memory on the
  stack using alloca() on systems where alloca() is present, or using
  the heap otherwise. The handler function takes a user provided value,
  multiplies it, and then passes it to the above macro. This results in
  both an integer overflow vulnerability, and an alloca() stack pointer
  shifting vulnerability. Both can be exploited to execute arbitrary
  code. (CVE-2007-1003)
  
  iDefense reported two integer overflows in the way X.org handled
  various font files. A malicious local user could exploit these issues
  to potentially execute arbitrary code with the privileges of the
  X.org server. (CVE-2007-1351, CVE-2007-1352)
  
  Multiple integer overflows in (1) the XGetPixel function in ImUtil.c
  in x.org libx11 before 1.0.3, and (2) XInitImage function in xwd.c for
  ImageMagick, allow user-assisted remote attackers to cause a denial
  of service (crash) or information leak via crafted images with large
  or negative values that trigger a buffer overflow. (CVE-2007-1667)
  
  Updated packages are patched to address these issues.
  
  Update:
  
  Packages for Mandriva Linux 2007.1 are now available.";

tag_affected = "xorg-x11 on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-04/msg00016.php");
  script_oid("1.3.6.1.4.1.25623.1.0.307854");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:079-1");
  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
  script_name( "Mandriva Update for xorg-x11 MDKSA-2007:079-1 (xorg-x11)");

  script_tag(name:"summary", value:"Check for the Version of xorg-x11");
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

  if ((res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libx11_6-devel", rpm:"libx11_6-devel~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libx11_6-static-devel", rpm:"libx11_6-static-devel~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxfont1", rpm:"libxfont1~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxfont1-devel", rpm:"libxfont1-devel~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxfont1-static-devel", rpm:"libxfont1-static-devel~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server", rpm:"x11-server~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-common", rpm:"x11-server-common~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-devel", rpm:"x11-server-devel~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xati", rpm:"x11-server-xati~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xchips", rpm:"x11-server-xchips~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xdmx", rpm:"x11-server-xdmx~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xephyr", rpm:"x11-server-xephyr~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xepson", rpm:"x11-server-xepson~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xfake", rpm:"x11-server-xfake~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xfbdev", rpm:"x11-server-xfbdev~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xgl", rpm:"x11-server-xgl~0.0.1~0.20070105.4.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xi810", rpm:"x11-server-xi810~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xmach64", rpm:"x11-server-xmach64~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xmga", rpm:"x11-server-xmga~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xneomagic", rpm:"x11-server-xneomagic~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xnest", rpm:"x11-server-xnest~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xnvidia", rpm:"x11-server-xnvidia~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xorg", rpm:"x11-server-xorg~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xpm2", rpm:"x11-server-xpm2~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xprt", rpm:"x11-server-xprt~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xr128", rpm:"x11-server-xr128~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xsdl", rpm:"x11-server-xsdl~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xsmi", rpm:"x11-server-xsmi~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xvesa", rpm:"x11-server-xvesa~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xvfb", rpm:"x11-server-xvfb~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xvia", rpm:"x11-server-xvia~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x11-server-xvnc", rpm:"x11-server-xvnc~1.2.0~8.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxfont", rpm:"libxfont~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64x11_6-devel", rpm:"lib64x11_6-devel~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64x11_6-static-devel", rpm:"lib64x11_6-static-devel~1.1.1~2.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xfont1", rpm:"lib64xfont1~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xfont1-devel", rpm:"lib64xfont1-devel~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xfont1-static-devel", rpm:"lib64xfont1-static-devel~1.2.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
