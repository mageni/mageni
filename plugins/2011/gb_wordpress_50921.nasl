###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_50921.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# WordPress Pretty Link Plugin 'pretty-bar.php' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103358");
  script_bugtraq_id(50921);
  script_version("$Revision: 12018 $");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("WordPress Pretty Link Plugin 'pretty-bar.php' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50921");
  script_xref(name:"URL", value:"http://wordpress.org/");
  script_xref(name:"URL", value:"http://www.wordpress.org/extend/plugins/pretty-link/changelog/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-07 10:18:02 +0100 (Wed, 07 Dec 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name:"summary", value:"The Pretty Link plugin for WordPress is prone to a cross-site
scripting vulnerability because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

Pretty Link 1.5.2 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Upgrade to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = string(dir, '/wp-content/plugins/pretty-link/pretty-bar.php?url="><script>alert(/openvas-xss-test/)</script>');

if(http_vuln_check(port:port,  url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE,extra_check:"Pretty Link")) {

  security_message(port:port);
  exit(0);

}

exit(0);
