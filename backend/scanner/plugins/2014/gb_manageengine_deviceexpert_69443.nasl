###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_deviceexpert_69443.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ManageEngine DeviceExpert User Credentials Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105085");
  script_bugtraq_id(69443);
  script_cve_id("CVE-2014-5377");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11867 $");

  script_name("ManageEngine DeviceExpert User Credentials Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69443");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/device-expert/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to obtain potentially sensitive
information. Information obtained may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Access '/ReadUsersFromMasterServlet' and check the response");

  script_tag(name:"insight", value:"ManageEngine DeviceExpert exposes user names and password hashes via
a GET request to 'ReadUsersFromMasterServlet'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"ManageEngine DeviceExpert is prone to an information-disclosure vulnerability.");

  script_tag(name:"affected", value:"ManageEngine DeviceExpert 5.9 Build 5980 is vulnerable. Other versions
may also be affected.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-09 14:44:24 +0200 (Tue, 09 Sep 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 6060);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


port = get_http_port( default:80 );

url = '/NCMContainer.cc';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>ManageEngine DeviceExpert" >!< buf ) exit( 0 );

url = '/ReadUsersFromMasterServlet';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<username>" >< buf && "<password>" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );


