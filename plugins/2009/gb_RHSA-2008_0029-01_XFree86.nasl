###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for XFree86 RHSA-2008:0029-01
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

tag_affected = "XFree86 on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1,
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-January/msg00013.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308146");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0029-01");
  script_cve_id("CVE-2007-4568", "CVE-2007-4990", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_name( "RedHat Update for XFree86 RHSA-2008:0029-01");

  script_tag(name:"summary", value:"Check for the Version of XFree86");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"XFree86-100dpi-fonts", rpm:"XFree86-100dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86", rpm:"XFree86~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-75dpi-fonts", rpm:"XFree86-75dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-100dpi-fonts", rpm:"XFree86-ISO8859-15-100dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-75dpi-fonts", rpm:"XFree86-ISO8859-15-75dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-100dpi-fonts", rpm:"XFree86-ISO8859-2-100dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-75dpi-fonts", rpm:"XFree86-ISO8859-2-75dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-100dpi-fonts", rpm:"XFree86-ISO8859-9-100dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-75dpi-fonts", rpm:"XFree86-ISO8859-9-75dpi-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xnest", rpm:"XFree86-Xnest~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xvfb", rpm:"XFree86-Xvfb~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-cyrillic-fonts", rpm:"XFree86-cyrillic-fonts~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-devel", rpm:"XFree86-devel~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-doc", rpm:"XFree86-doc~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs", rpm:"XFree86-libs~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-tools", rpm:"XFree86-tools~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-twm", rpm:"XFree86-twm~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xdm", rpm:"XFree86-xdm~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xf86cfg", rpm:"XFree86-xf86cfg~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xfs", rpm:"XFree86-xfs~4.1.0~85.EL", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"XFree86-100dpi-fonts", rpm:"XFree86-100dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86", rpm:"XFree86~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-75dpi-fonts", rpm:"XFree86-75dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-14-100dpi-fonts", rpm:"XFree86-ISO8859-14-100dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-14-75dpi-fonts", rpm:"XFree86-ISO8859-14-75dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-100dpi-fonts", rpm:"XFree86-ISO8859-15-100dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-75dpi-fonts", rpm:"XFree86-ISO8859-15-75dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-100dpi-fonts", rpm:"XFree86-ISO8859-2-100dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-75dpi-fonts", rpm:"XFree86-ISO8859-2-75dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-100dpi-fonts", rpm:"XFree86-ISO8859-9-100dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-75dpi-fonts", rpm:"XFree86-ISO8859-9-75dpi-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Mesa-libGL", rpm:"XFree86-Mesa-libGL~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Mesa-libGLU", rpm:"XFree86-Mesa-libGLU~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xnest", rpm:"XFree86-Xnest~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xvfb", rpm:"XFree86-Xvfb~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-base-fonts", rpm:"XFree86-base-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-cyrillic-fonts", rpm:"XFree86-cyrillic-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-devel", rpm:"XFree86-devel~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-doc", rpm:"XFree86-doc~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-font-utils", rpm:"XFree86-font-utils~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs", rpm:"XFree86-libs~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs-data", rpm:"XFree86-libs-data~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-sdk", rpm:"XFree86-sdk~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-syriac-fonts", rpm:"XFree86-syriac-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-tools", rpm:"XFree86-tools~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-truetype-fonts", rpm:"XFree86-truetype-fonts~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-twm", rpm:"XFree86-twm~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xauth", rpm:"XFree86-xauth~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xdm", rpm:"XFree86-xdm~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xfs", rpm:"XFree86-xfs~4.3.0~125.EL", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
