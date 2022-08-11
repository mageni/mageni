###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for cups CESA-2008:0206 centos3 x86_64
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
tag_insight = "The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
  attacker could create a malicious HP-GL/2 file that could possibly execute
  arbitrary code as the &quot;lp&quot; user if the file is printed. (CVE-2008-0053)
  
  A buffer overflow flaw was discovered in the GIF decoding routines used by
  CUPS image converting filters &quot;imagetops&quot; and &quot;imagetoraster&quot;. An attacker
  could create a malicious GIF file that could possibly execute arbitrary
  code as the &quot;lp&quot; user if the file was printed. (CVE-2008-1373)
  
  It was discovered that the patch used to address CVE-2004-0888 in CUPS
  packages in Red Hat Enterprise Linux 3 and 4 did not completely resolve the
  integer overflow in the &quot;pdftops&quot; filter on 64-bit platforms.  An attacker
  could create a malicious PDF file that could possibly execute arbitrary
  code as the &quot;lp&quot; user if the file was printed. (CVE-2008-1374)
  
  All cups users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "cups on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-April/014796.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307493");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0053", "CVE-2008-1373", "CVE-2008-1374", "CVE-2004-0888", "CVE-2005-0206");
  script_name( "CentOS Update for cups CESA-2008:0206 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of cups");
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

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.52", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.52", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.52", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
