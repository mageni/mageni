###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_statistics_sql_injection_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# WordPress WP Statistics Authenticated SQL Injection Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810967");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-03 12:40:08 +0530 (Mon, 03 Jul 2017)");
  script_name("WordPress WP Statistics Authenticated SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running WordPress WP Statistics plugin
  and is prone to a sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"This script sends HTTP GET request and try to
  get the version from the response and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to the lack of
  sanitization in user-provided data for some attributes of the shortcode
  wpstatistics which are passed as parameters for important functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers with at least a subscriber account could leak sensitive data and
  under the right circumstances/configurations compromise your WordPress
  installation.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin 12.0.7
  and earlier.");

  script_tag(name:"solution", value:"Upgrade to WordPress WP Statistics plugin
  12.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8854");
  script_xref(name:"URL", value:"http://thehackernews.com/2017/06/wordpress-hacking-sql-injection.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-statistics");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:wpPort)){
  exit(0);
}

if( dir == "/" ) dir = "";

rcvRes = http_get_cache(port: wpPort, item: dir + "/wp-content/plugins/wp-statistics/readme.txt");

if( rcvRes =~ "HTTP/1.. 200" && 'WP Statistics' >< rcvRes && "Changelog" >< rcvRes)
{
  ver = eregmatch(pattern:'Stable tag: ([0-9.]+)', string:rcvRes);
  if(ver[1])
  {
    if(version_is_less(version:ver[1], test_version:"12.0.8"))
    {
      report = report_fixed_ver(installed_version:ver[1], fixed_version:"12.0.8");
      security_message(data:report, port:wpPort);
      exit(0);
    }
  }
}
exit(0);
