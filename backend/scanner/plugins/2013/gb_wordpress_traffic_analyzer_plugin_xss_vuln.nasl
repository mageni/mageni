###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_traffic_analyzer_plugin_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# WordPress Traffic Analyzer Plugin XSS Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803372");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3526");
  script_bugtraq_id(58948);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-12 17:30:46 +0530 (Fri, 12 Apr 2013)");
  script_name("WordPress Traffic Analyzer Plugin XSS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52929");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121167");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-traffic-analyzer-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.");
  script_tag(name:"affected", value:"WordPress Traffic Analyzer Plugin version 3.3.2 and prior");
  script_tag(name:"insight", value:"The input passed via 'aoid' parameters to
'/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php' script is not
properly validated.");
  script_tag(name:"solution", value:"Upgrade to WordPress Traffic Analyzer Plugin version 3.4.0 or
later.");
  script_tag(name:"summary", value:"This host is running WordPress with Traffic Analyzer plugin and
is prone to cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/trafficanalyzer");
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

url = dir + '/wp-content/plugins/trafficanalyzer/js/ta_loaded.js.php?aoid='+
            '"><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>"))
{
  security_message(port:port);
  exit(0);
}
