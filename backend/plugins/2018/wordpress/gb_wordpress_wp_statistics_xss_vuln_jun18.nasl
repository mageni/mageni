###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress WP Statistics Cross Site Scripting (XSS) Vulnerability-June18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813453");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-1000556");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-27 12:29:51 +0530 (Wed, 27 Jun 2018)");
  script_name("WordPress WP Statistics Cross Site Scripting (XSS) Vulnerability-June18");

  script_tag(name:"summary", value:"This host is running WordPress WP Statistics plugin
  and is prone to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"This script sends HTTP GET request and try to
  get the version from the response and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to the lack of sanitization
  in user-provided data for '/includes/log/page-statistics.php' script  via
  'page-uri' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code via crafted data.");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin prior to
  version 12.0.6");

  script_tag(name:"solution", value:"Upgrade to WordPress WP Statistics plugin
  12.0.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-statistics");
  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2017/04/28/reflected-cross-site-scripting-xss-vulnerability-in-wp-statistics/");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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

if(rcvRes =~ "HTTP/1.. 200" && 'WP Statistics' >< rcvRes && "Changelog" >< rcvRes)
{
  ver = eregmatch(pattern:'Stable tag: ([0-9.]+)', string:rcvRes);
  if(ver[1])
  {
    if(version_is_less(version:ver[1], test_version:"12.0.6"))
    {
      report = report_fixed_ver(installed_version:ver[1], fixed_version:"12.0.6");
      security_message(data:report, port:wpPort);
      exit(0);
    }
  }
}
exit(0);
