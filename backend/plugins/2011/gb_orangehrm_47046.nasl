###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orangehrm_47046.nasl 11235 2018-09-05 08:57:41Z cfischer $
#
# OrangeHRM 'jobVacancy.php' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:orangehrm:orangehrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103132");
  script_version("$Revision: 11235 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-05 10:57:41 +0200 (Wed, 05 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-03-28 19:09:51 +0200 (Mon, 28 Mar 2011)");
  script_bugtraq_id(47046);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("OrangeHRM 'jobVacancy.php' Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orangehrm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("orangehrm/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47046");
  script_xref(name:"URL", value:"http://www.orangehrm.com/");

  script_tag(name:"summary", value:"OrangeHRM is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input before using it in
  dynamically generated content.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker
  to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"OrangeHRM 2.6.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";
url = dir + "/templates/recruitment/jobVacancy.php?recruitcode=</script><script>alert('openvas-xss-test')</script>";

if( http_vuln_check( port:port, url:url, pattern:"><script>alert\('openvas-xss-test'\)</script>", extra_check:"Employee", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
