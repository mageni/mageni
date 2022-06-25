###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xorg-x11 CESA-2008:0030 centos4 i386
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
tag_insight = "The xorg-x11 packages contain X.Org, an open source implementation of the X
  Window System. It provides the basic low-level functionality that
  full-fledged graphical user interfaces are designed upon.

  Two integer overflow flaws were found in the X.Org server's EVI and MIT-SHM
  modules. A malicious authorized client could exploit these issues to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the X.Org server. (CVE-2007-6429)
  
  A heap based buffer overflow flaw was found in the way the X.Org server
  handled malformed font files. A malicious local user could exploit these
  issues to potentially execute arbitrary code with the privileges of the
  X.Org server. (CVE-2008-0006)
  
  A memory corruption flaw was found in the X.Org server's XInput extension.
  A malicious authorized client could exploit this issue to cause a denial of
  service (crash), or potentially execute arbitrary code with root privileges
  on the X.Org server. (CVE-2007-6427)
  
  An input validation flaw was found in the X.Org server's XFree86-Misc
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially execute arbitrary code with
  root privileges on the X.Org server. (CVE-2007-5760)
  
  An information disclosure flaw was found in the X.Org server's TOG-CUP
  extension. A malicious authorized client could exploit this issue to cause
  a denial of service (crash), or potentially view arbitrary memory content
  within the X server's address space. (CVE-2007-6428)
  
  An integer and heap overflow flaw were found in the X.Org font server, xfs.
  A user with the ability to connect to the font server could have been able
  to cause a denial of service (crash), or potentially execute arbitrary code
  with the permissions of the font server. (CVE-2007-4568, CVE-2007-4990)
  
  A flaw was found in the X.Org server's XC-SECURITY extension, that could
  have allowed a local user to verify the existence of an arbitrary file,
  even in directories that are not normally accessible to that user.
  (CVE-2007-5958)
  
  Users of xorg-x11 should upgrade to these updated packages, which contain
  backported patches to resolve these issues.";

tag_affected = "xorg-x11 on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-January/014648.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311250");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_name( "CentOS Update for xorg-x11 CESA-2008:0030 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of xorg-x11");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-deprecated-libs", rpm:"xorg-x11-deprecated-libs~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-deprecated-libs-devel", rpm:"xorg-x11-deprecated-libs-devel~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-font-utils", rpm:"xorg-x11-font-utils~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Mesa-libGL", rpm:"xorg-x11-Mesa-libGL~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Mesa-libGLU", rpm:"xorg-x11-Mesa-libGLU~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-sdk", rpm:"xorg-x11-sdk~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-tools", rpm:"xorg-x11-tools~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-twm", rpm:"xorg-x11-twm~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xauth", rpm:"xorg-x11-xauth~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xdm", rpm:"xorg-x11-xdm~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xdmx", rpm:"xorg-x11-Xdmx~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xfs", rpm:"xorg-x11-xfs~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xnest", rpm:"xorg-x11-Xnest~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvfb", rpm:"xorg-x11-Xvfb~6.8.2~1.EL.33.0.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
