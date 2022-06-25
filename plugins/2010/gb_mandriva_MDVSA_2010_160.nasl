###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for cacti MDVSA-2010:160 (cacti)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in cacti:

  Multiple cross-site scripting (XSS) vulnerabilities in Cacti before
  0.8.7f, allow remote attackers to inject arbitrary web script or
  HTML via the (1) hostname or (2) description parameter to host.php,
  or (3) the host_id parameter to data_sources.php (CVE-2010-1644).

  Cacti before 0.8.7f, allows remote authenticated administrators to
  execute arbitrary commands via shell metacharacters in (1) the FQDN
  field of a Device or (2) the Vertical Label field of a Graph Template
  (CVE-2010-1645).

  Cross-site scripting (XSS) vulnerability in
  include/top_graph_header.php in Cacti before 0.8.7g allows remote
  attackers to inject arbitrary web script or HTML via the graph_start
  parameter to graph.php.  NOTE: this vulnerability exists because of
  an incorrect fix for CVE-2009-4032.2.b (CVE-2010-2543).

  Cross-site scripting (XSS) vulnerability in utilities.php in Cacti
  before 0.8.7g, allows remote attackers to inject arbitrary web script
  or HTML via the filter parameter (CVE-2010-2544).

  Multiple cross-site scripting (XSS) vulnerabilities in Cacti before
  0.8.7g, allow remote attackers to inject arbitrary web script or HTML
  via (1) the name element in an XML template to templates_import.php;
  and allow remote authenticated administrators to inject arbitrary web
  script or HTML via vectors related to (2) cdef.php, (3) data_input.php,
  (4) data_queries.php, (5) data_sources.php, (6) data_templates.php, (7)
  gprint_presets.php, (8) graph.php, (9) graphs_new.php, (10) graphs.php,
  (11) graph_templates_inputs.php, (12) graph_templates_items.php,
  (13) graph_templates.php, (14) graph_view.php, (15) host.php, (16)
  host_templates.php, (17) lib/functions.php, (18) lib/html_form.php,
  (19) lib/html_form_template.php, (20) lib/html.php, (21)
  lib/html_tree.php, (22) lib/rrd.php, (23) rra.php, (24) tree.php,
  and (25) user_admin.php (CVE-2010-2545).

  This update provides cacti 0.8.7f, which is not vulnerable to these
  issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "cacti on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-08/msg00021.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312844");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:59:25 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:160");
  script_cve_id("CVE-2010-1644", "CVE-2010-1645", "CVE-2009-4032", "CVE-2010-2543", "CVE-2010-2544", "CVE-2010-2545");
  script_name("Mandriva Update for cacti MDVSA-2010:160 (cacti)");

  script_tag(name: "summary" , value: "Check for the Version of cacti");
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

  if ((res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.7g~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
