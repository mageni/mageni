###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_wcm_64496.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# IBM Web Content Manager 'LIBRARY' Parameter XPath Injection Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103882");
  script_bugtraq_id(64496);
  script_cve_id("CVE-2013-6735");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11867 $");

  script_name("IBM Web Content Manager 'LIBRARY' Parameter XPath Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64496");
  script_xref(name:"URL", value:"http://www.ibm.com/");
  script_xref(name:"URL", value:"http://www-306.ibm.com/software/websphere/portal/");
  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20131227-0_IBM_WCM_XPath_Injection_v10.txt");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-15 16:11:31 +0100 (Wed, 15 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker can exploit this issue by manipulating the XPath query
logic to carry out unauthorized actions on the application.");
  script_tag(name:"vuldetect", value:"Send some special crafted HTTP GET requests and check the response.");
  script_tag(name:"insight", value:"Due to insufficient validation, the 'LIBRARY' element suffers from an
XPath-injection vulnerability.

An unauthenticated user is able to perform blind XPath Injection attacks e.g.
get current application configuration, enumerate nodes and extract other
valuable information from vulnerable installations of Web Content Manager.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"summary", value:"IBM Web Content Manager is prone to an XPath-injection vulnerability.");
  script_tag(name:"affected", value:"IBM WebSphere Portal 6.0.0.x through 6.0.0.1,

6.0.1.x through 6.0.1.7,

6.1.0.x through 6.1.0.6 CF27,

6.1.5.x through 6.1.5.3 CF27,

7.0.0.x through 7.0.0.2 CF26,

8.0.0.x through 8.0.0.1 CF08");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");


port = get_http_port( default:80 );

url = "/wps/wcm/connect/%27%20or%20%27a%27%3d%27b";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "HTTP/1\.. 404" ) exit (0);

url = "/wps/wcm/connect/%27%20or%20%27a%27%3d%27a";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 302" && buf =~ 'Location:.*/wps/wcm/webinterface/login/login.jsp' )
{
  security_message( port:port );
  exit(0);
}

exit (99);
