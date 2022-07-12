###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_count_per_day_plugin_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Wordpress Count per Day Plugin Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803430");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-06 11:34:32 +0530 (Wed, 06 Mar 2013)");
  script_name("Wordpress Count per Day Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/43");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/48");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML or web script in a user's browser session in context of an affected site,
cause denial of service, and discloses the software installation path results
in a loss of confidentiality.");
  script_tag(name:"affected", value:"WordPress Count per Day plugin <= 3.2.5");
  script_tag(name:"insight", value:"- Malicious input passed via 'daytoshow' parameter to /wp-content
/wp-admin/index.php script is not properly sanitised before being returned to
the user.

  - Malicious input passed via POST parameters to wordpress/wp-content/plugins
/count-per-day/notes.php script is not properly sanitised before being
returned to the user.

  - Malformed GET request to ajax.php, counter-core.php, counter-options.php,
counter.php, massbots.php, and userperspan.php scripts.");
  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");
  script_tag(name:"summary", value:"This host is running WordPress with Count per Day plugin and is
prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/count-per-day");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

url = dir + '/wp-content/plugins/count-per-day/ajax.php';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<b>Notice</b>:  Undefined index: f in.*ajax.php"))
{
  security_message(port:port);
  exit(0);
}
