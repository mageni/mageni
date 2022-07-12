###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_server_41389.nasl 12513 2018-11-23 14:24:09Z cfischer $
#
# Sun Java System Web Server Admin Interface Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100703");
  script_version("$Revision: 12513 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 15:24:09 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(41389);
  script_name("Sun Java System Web Server Admin Interface Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
  script_require_ports("Services/www", 8989);
  script_mandatory_keys("Sun/JavaSysWebServ/Ver", "Sun/JavaSysWebServ/Port");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41389");
  script_xref(name:"URL", value:"http://www.sun.com/software/products/web_srvr/home_web_srvr.xml");

  script_tag(name:"summary", value:"Sun Java System Web Server is prone to a denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the effected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Sun Java System Web Server 7.0 Update 7 is affected. Other versions
  may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

sysWebVer = get_kb_item( "Sun/JavaSysWebServ/Ver" );
if( ! sysWebVer || sysWebVer !~ "^7\.0" ) exit( 0 );

port = get_http_port( default:8989 );
if( ! version = get_kb_item( "Sun/JavaSysWebServ/" + port + "/Ver" ) ) exit( 0 );

vers = str_replace( find:"U", string:version, replace:"." );
if( version_in_range( version:vers, test_version: "7.0.0", test_version2:"7.0.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );