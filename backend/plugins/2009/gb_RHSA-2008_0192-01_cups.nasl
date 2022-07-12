###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cups RHSA-2008:0192-01
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

  A heap buffer overflow flaw was found in a CUPS administration interface
  CGI script. A local attacker able to connect to the IPP port (TCP port 631)
  could send a malicious request causing the script to crash or, potentially,
  execute arbitrary code as the &quot;lp&quot; user. Please note: the default CUPS
  configuration in Red Hat Enterprise Linux 5 does not allow remote
  connections to the IPP TCP port. (CVE-2008-0047)
  
  Red Hat would like to thank &quot;regenrecht&quot; for reporting this issue.
  
  This issue did not affect the versions of CUPS as shipped with Red Hat
  Enterprise Linux 3 or 4.
  
  Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
  attacker could create a malicious HP-GL/2 file that could possibly execute
  arbitrary code as the &quot;lp&quot; user if the file is printed. (CVE-2008-0053)
  
  A buffer overflow flaw was discovered in the GIF decoding routines used by
  CUPS image converting filters &quot;imagetops&quot; and &quot;imagetoraster&quot;. An attacker
  could create a malicious GIF file that could possibly execute arbitrary
  code as the &quot;lp&quot; user if the file was printed. (CVE-2008-1373)
  
  All cups users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "cups on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-April/msg00000.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309141");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0192-01");
  script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-1373");
  script_name( "RedHat Update for cups RHSA-2008:0192-01");

  script_tag(name:"summary", value:"Check for the Version of cups");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.2.4~11.14.el5_1.6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.2.4~11.14.el5_1.6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.2.4~11.14.el5_1.6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.2.4~11.14.el5_1.6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.2.4~11.14.el5_1.6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
