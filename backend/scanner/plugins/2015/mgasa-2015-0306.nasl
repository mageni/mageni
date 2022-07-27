###############################################################################
# OpenVAS Vulnerability Test
# $Id: mgasa-2015-0306.nasl 11692 2018-09-28 16:55:19Z cfischer $
#
# Mageia Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130073");
  script_version("$Revision: 11692 $");
  script_tag(name:"creation_date", value:"2015-10-15 10:42:23 +0300 (Thu, 15 Oct 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 18:55:19 +0200 (Fri, 28 Sep 2018) $");
  script_name("Mageia Linux Local Check: mgasa-2015-0306");
  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in Cacti before 0.8.8d allows remote attackers to inject arbitrary web script or HTML via unspecified vectors (CVE-2015-2665). SQL injection vulnerability in Cacti before 0.8.8d allows remote attackers to execute arbitrary SQL commands via unspecified vectors involving a cdef id (CVE-2015-4342). SQL injection vulnerability in the get_hash_graph_template function in lib/functions.php in Cacti before 0.8.8d allows remote attackers to execute arbitrary SQL commands via the graph_template_id parameter to graph_templates.php (CVE-2015-4454). SQL injection vulnerability in Cacti before 0.8.8e in graphs.php (CVE-2015-4634). The cacti package has been updated to version 0.8.8e, which fixes this issue, as well as other SQL injection and XSS issues and other bugs");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0306.html");
  script_cve_id("CVE-2015-2665", "CVE-2015-4342", "CVE-2015-4454", "CVE-2015-4634");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Mageia Linux Local Security Checks mgasa-2015-0306");
  script_copyright("Eero Volotinen");
  script_family("Mageia Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"cacti", rpm:"cacti~0.8.8f~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
