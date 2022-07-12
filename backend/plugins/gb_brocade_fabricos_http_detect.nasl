###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_fabricos_http_detect.nasl 8828 2018-02-15 11:52:02Z cfischer $
#
# Brocade Fabric OS Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108336");
  script_version("$Revision: 8828 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-15 12:52:02 +0100 (Thu, 15 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Brocade Fabric OS Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the device and attempts
  to detect the presence of devices running Fabric OS and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

buf = http_get_cache( item:"/", port:port );

if( buf !~ "^HTTP/1\.[01] 302" || "switchExplorer.html" >!< buf ) exit( 0 );

# nb: Older devices don't have this page
url1 = "/switchExplorer_installed.html";
req1 = http_get( item:url1, port:port );
buf1 = http_keepalive_send_recv( port:port, data:req1, bodyonly:TRUE );

url2 = "/switchExplorer.html";
req2 = http_get( item:url2, port:port );
buf2 = http_keepalive_send_recv( port:port, data:req2, bodyonly:TRUE );

# Another variant on branded devices like Connectrix
url3 = "/LoginApplet.html";
req3 = http_get( item:url3, port:port );
buf3 = http_keepalive_send_recv( port:port, data:req3, bodyonly:TRUE );

if( '<application-desc main-class="com.brocade.web' >< buf1 ||
    'CODE="com.brocade.web' >< buf2 ||
    'CODE="com.brocade.web' >< buf3 ) {

  version = "unknown";
  set_kb_item( name:"brocade_fabricos/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/http/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/http/port", value:port );

  vers = eregmatch( pattern:"<vendor>v([0-9a-z.]+)</vendor>", string:buf1 );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"brocade_fabricos/http/" + port + "/concluded", value:vers[0] );
    set_kb_item( name:"brocade_fabricos/http/" + port + "/concludedUrl", value:report_vuln_url( port:port, url:url1, url_only:TRUE ) );
  }

  set_kb_item( name:"brocade_fabricos/http/" + port + "/version", value:version );
}

exit( 0 );
