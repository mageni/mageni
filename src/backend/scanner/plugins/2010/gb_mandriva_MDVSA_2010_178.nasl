###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for ocsinventory MDVSA-2010:178 (ocsinventory)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in ocsinventory:

  Multiple cross-site scripting (XSS) vulnerabilities in
  ocsreports/index.php in OCS Inventory NG 1.02.1 allow remote attackers
  to inject arbitrary web script or HTML via (1) the query string, (2)
  the BASE parameter, or (3) the ega_1 parameter.  NOTE: some of these
  details are obtained from third party information (CVE-2010-1594).
  
  Multiple SQL injection vulnerabilities in ocsreports/index.php in
  OCS Inventory NG 1.02.1 allow remote attackers to execute arbitrary
  SQL commands via the (1) c, (2) val_1, or (3) onglet_bis parameter
  (CVE-2010-1595).
  
  Multiple SQL injection vulnerabilities in OCS Inventory NG before
  1.02.3 allow remote attackers to execute arbitrary SQL commands via
  (1) multiple inventory fields to the search form, reachable through
  index.php; or (2) the Software name field to the All softwares search
  form, reachable through index.php.  NOTE: the provenance of this
  information is unknown; the details are obtained solely from third
  party information (CVE-2010-1733).
  
  This upgrade provides ocsinventory 1.02.3 which is not vulnerable
  for these security issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "ocsinventory on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00012.php");
  script_oid("1.3.6.1.4.1.25623.1.0.315119");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-14 15:35:55 +0200 (Tue, 14 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:178");
  script_cve_id("CVE-2010-1594", "CVE-2010-1595", "CVE-2010-1733");
  script_name("Mandriva Update for ocsinventory MDVSA-2010:178 (ocsinventory)");

  script_tag(name: "summary" , value: "Check for the Version of ocsinventory");
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

  if ((res = isrpmvuln(pkg:"ocsinventory-reports", rpm:"ocsinventory-reports~1.02.3~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocsinventory-server", rpm:"ocsinventory-server~1.02.3~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocsinventory", rpm:"ocsinventory~1.02.3~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
