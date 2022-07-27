###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for XFree86-100dpi-fonts CESA-2008:0029 centos3 x86_64
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
tag_insight = "XFree86 is an implementation of the X Window System, which provides the
  core functionality for the Linux graphical desktop.

  Two integer overflow flaws were found in the XFree86 server's EVI and
  MIT-SHM modules. A malicious authorized client could exploit these issues
  to cause a denial of service (crash), or potentially execute arbitrary code
  with root privileges on the XFree86 server. (CVE-2007-6429)
  
  A heap based buffer overflow flaw was found in the way the XFree86 server
  handled malformed font files. A malicious local user could exploit this
  issue to potentially execute arbitrary code with the privileges of the
  XFree86 server. (CVE-2008-0006)
  
  A memory corruption flaw was found in the XFree86 server's XInput
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the XFree86 server. (CVE-2007-6427)
  
  An information disclosure flaw was found in the XFree86 server's TOG-CUP
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially view arbitrary memory content
  within the XFree86 server's address space. (CVE-2007-6428)
  
  An integer and heap overflow flaw were found in the X.org font server, xfs.
  A user with the ability to connect to the font server could have been able
  to cause a denial of service (crash), or potentially execute arbitrary code
  with the permissions of the font server. (CVE-2007-4568, CVE-2007-4990)
  
  A flaw was found in the XFree86 server's XC-SECURITY extension, that could
  have allowed a local user to verify the existence of an arbitrary file,
  even in directories that are not normally accessible to that user.
  (CVE-2007-5958)
  
  Users of XFree86 are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "XFree86-100dpi-fonts on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014619.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305944");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_name( "CentOS Update for XFree86-100dpi-fonts CESA-2008:0029 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of XFree86-100dpi-fonts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"XFree86-100dpi-fonts", rpm:"XFree86-100dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86", rpm:"XFree86~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-75dpi-fonts", rpm:"XFree86-75dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-base-fonts", rpm:"XFree86-base-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-cyrillic-fonts", rpm:"XFree86-cyrillic-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-devel", rpm:"XFree86-devel~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-doc", rpm:"XFree86-doc~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-font-utils", rpm:"XFree86-font-utils~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-14-100dpi-fonts", rpm:"XFree86-ISO8859-14-100dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-14-75dpi-fonts", rpm:"XFree86-ISO8859-14-75dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-100dpi-fonts", rpm:"XFree86-ISO8859-15-100dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-75dpi-fonts", rpm:"XFree86-ISO8859-15-75dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-100dpi-fonts", rpm:"XFree86-ISO8859-2-100dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-75dpi-fonts", rpm:"XFree86-ISO8859-2-75dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-100dpi-fonts", rpm:"XFree86-ISO8859-9-100dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-75dpi-fonts", rpm:"XFree86-ISO8859-9-75dpi-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs", rpm:"XFree86-libs~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs-data", rpm:"XFree86-libs-data~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Mesa-libGL", rpm:"XFree86-Mesa-libGL~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Mesa-libGLU", rpm:"XFree86-Mesa-libGLU~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-sdk", rpm:"XFree86-sdk~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-syriac-fonts", rpm:"XFree86-syriac-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-tools", rpm:"XFree86-tools~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-truetype-fonts", rpm:"XFree86-truetype-fonts~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-twm", rpm:"XFree86-twm~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xauth", rpm:"XFree86-xauth~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xdm", rpm:"XFree86-xdm~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xfs", rpm:"XFree86-xfs~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xnest", rpm:"XFree86-Xnest~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xvfb", rpm:"XFree86-Xvfb~4.3.0~125.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
