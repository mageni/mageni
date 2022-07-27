###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_service_tag_info_disclosure.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Dell Foundation Services Service Tag Remote Information Disclosure
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105475");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-03 10:52:22 +0100 (Thu, 03 Dec 2015)");
  script_name("Dell Foundation Services 'Service Tag' Remote Information Disclosure");

  script_tag(name:"summary", value:"An issue in Dell Foundation Services, version 2.3.3800.0A00 and below, can be exploited by a malicious website to leak the Dell service tag of a Dell system, which can be used for tracking purposes, or for social engineering.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"Update to a Dell Foundation Services > 2.3.3800.0A00 or uninstall Dell Foundation Services");
  script_tag(name:"insight", value:"Dell Foundation Services starts a HTTPd that listens on port 7779. Generally, requests to the API exposed by this HTTPd must be requests signed using a RSA-1024 key and hashed with SHA512.
One of the JSONP API endpoints to obtain the service tag does not need a valid signature to be provided. Thus, any website can call it.");
  script_tag(name:"affected", value:"Dell Foundation Services 2.3.3800.0A00 and below.");

  script_xref(name:"URL", value:"http://lizardhq.rum.supply/2015/11/25/dell-foundation-services.html");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 7779);
  script_mandatory_keys("Microsoft-HTTPAPI/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:7779 );
banner = get_http_banner( port:port );

if( "Microsoft-HTTPAPI" >!< banner || "404 Not Found" >!< banner ) exit( 0 );

url = '/Dell%20Foundation%20Services/eDell/IeDellCapabilitiesApi/REST/ServiceTag';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ 'HTTP/1\\.. 200' && "application/json" >< buf )
{
  hb = split( buf, sep:'\r\n\r\n', keep:FALSE );
  if( isnull( hb[1] ) ) exit( 0 );
  body = str_replace( string: hb[1], find:'\r\n', replace:'' );

  if( body =~ '^"[A-Za-z0-9]+"$' )
  {
    rep = report_vuln_url( port:port, url:url );
    rep += '\nDell Service Tag: ' + body;

    security_message( port:port, data:rep );
    exit( 0 );
  }
}

exit( 0 );
