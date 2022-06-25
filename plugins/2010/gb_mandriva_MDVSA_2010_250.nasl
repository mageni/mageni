###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for perl-CGI-Simple MDVSA-2010:250 (perl-CGI-Simple)
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
tag_insight = "A vulnerability was discovered and corrected in perl-CGI-Simple:

  The multipart_init function in (1) CGI.pm before 3.50 and (2) Simple.pm
  in CGI::Simple 1.112 and earlier uses a hardcoded value of the MIME
  boundary string in multipart/x-mixed-replace content, which allows
  remote attackers to inject arbitrary HTTP headers and conduct HTTP
  response splitting attacks via crafted input that contains this value,
  a different vulnerability than CVE-2010-3172 (CVE-2010-2761).
  
  The updated packages have been patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "perl-CGI-Simple on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-12/msg00009.php");
  script_oid("1.3.6.1.4.1.25623.1.0.315135");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-23 07:38:58 +0100 (Thu, 23 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "MDVSA", value: "2010:250");
  script_cve_id("CVE-2010-3172", "CVE-2010-2761");
  script_name("Mandriva Update for perl-CGI-Simple MDVSA-2010:250 (perl-CGI-Simple)");

  script_tag(name: "summary" , value: "Check for the Version of perl-CGI-Simple");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"perl-CGI-Simple", rpm:"perl-CGI-Simple~1.1~4.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
