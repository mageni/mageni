###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_rom_0.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Multiple Routers 'rom-0' Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103886");
  script_bugtraq_id(60682);
  script_version("$Revision: 14117 $");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");

  script_name("Multiple Routers 'rom-0' Vulnerability");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2014/01/20/tp-link-td-w8901g-router-multiple-vulnerabilities/");

  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-21 12:05:08 +0100 (Tue, 21 Jan 2014)");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security
  restrictions and obtain sensitive information which may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Request /rom-0 and check the response.");

  script_tag(name:"insight", value:"If you request the /rom-0 file it does not require
  authentication. This can be reversed using available tools zynos.php. The first string returned is the
  admin password.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"The remote Router is prone to the 'rom-0' Vulnerability.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( "Server: RomPager/" >!< banner ) exit (0);

req = http_get( item:'/rom-0', port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "dbgarea" >< buf && "spt.dat" >< buf )
{
  security_message( port:port );
  exit(0);
}

exit(99);