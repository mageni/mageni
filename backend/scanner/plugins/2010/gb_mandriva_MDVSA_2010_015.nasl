###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for roundcubemail MDVSA-2010:015 (roundcubemail)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in transmission:

  A number of dependency probles were discovered and has been corrected
  with this release (#56006).
  
  Cross-site request forgery (CSRF) vulnerability in Roundcube Webmail
  0.2.2 and earlier allows remote attackers to hijack the authentication
  of unspecified users for requests that modify user information via
  unspecified vectors, a different vulnerability than CVE-2009-4077
  (CVE-2009-4076).
  
  Cross-site request forgery (CSRF) vulnerability in Roundcube Webmail
  0.2.2 and earlier allows remote attackers to hijack the authentication
  of unspecified users for requests that send arbitrary emails via
  unspecified vectors, a different vulnerability than CVE-2009-4076
  (CVE-2009-4077).
  
  The updated packages have been patched to correct these
  issues. Additionally roundcubemail has been upgraded to 0.2.2 that
  also fixes a number of upstream bugs.";

tag_affected = "roundcubemail on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-01/msg00058.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312962");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-20 09:25:19 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:015");
  script_cve_id("CVE-2009-4077", "CVE-2009-4076");
  script_name("Mandriva Update for roundcubemail MDVSA-2010:015 (roundcubemail)");

  script_tag(name: "summary" , value: "Check for the Version of roundcubemail");
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

  if ((res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~0.2.2~0.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
