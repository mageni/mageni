###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_googlemaps_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Joomla Googlemaps Multiple Vulnerabilities
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

CPE = 'cpe:/a:joomla:joomla';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803836");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2013-7428", "CVE-2013-7429", "CVE-2013-7430", "CVE-2013-7431", "CVE-2013-7432", "CVE-2013-7433", "CVE-2013-7434");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-22 15:14:31 +0530 (Mon, 22 Jul 2013)");

  script_name("Joomla Googlemaps Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jul/158");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-googlemaps-xss-xml-injection-path-disclosure-dos");

  script_tag(name:"summary", value:"This host is running Joomla Googlemaps plugin and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not.");

  script_tag(name:"solution", value:"Upgrade to Googlemaps plugin for Joomla version 3.1 or later.");

  script_tag(name:"insight", value:"Input passed via 'url' parameter to 'plugin_googlemap2_proxy.php'
  is not properly sanitised before being returned to the user.");

  script_tag(name:"affected", value:"Googlemaps plugin for Joomla versions 2.x and 3.x and potentially
  previous versions may also be affected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary
  HTML or script code, discloses the software's installation path resulting in a
  loss of confidentiality.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://extensions.joomla.org/extensions/maps-a-weather/maps-a-locations/maps/1147");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port(cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/plugins/content/plugin_googlemap2_proxy.php" +
            "?url=%3Cbody%20onload=alert(document.cookie)%3E";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"onload=alert\(document.cookie\)",
                     extra_check:"Couldn't resolve host" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
