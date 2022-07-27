###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kunena_forum_detect.nasl 8139 2017-12-15 11:57:25Z cfischer $
#
# Kunena Forum Extension for Joomla Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:joomla:joomla';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108105");
  script_version("$Revision: 8139 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:57:25 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kunena Forum Extension for Joomla Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Detection of the Kunena forum extension for Joomla.

  The script sends a HTTP request to the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

install = dir;
if( dir == "/" ) dir = "";

url = dir + '/plugins/kunena/kunena/kunena.xml';
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

urls = dir + '/plugins/system/kunena/kunena.xml';
req2 = http_get( item:urls, port:port );
res2 = http_keepalive_send_recv( port:port, data:req );

if( "<name>plg_kunena_kunena</name>" >< res || "<name>plg_kunena_kunena</name>" >< res2 ) {

  version = "unknown";

  ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
  } else {
    ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res2 );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
    }
  }

  set_kb_item( name:"www/" + port + "/kunena_forum", value:version );
  set_kb_item( name:"kunena_forum/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kunena:kunena:");
  if( isnull( cpe ) )
    cpe = 'cpe:/a:kunena:kunena';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data: build_detection_report( app:"Kunena Forum Extension",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concludedUrl:conclUrl,
                                             concluded:ver[0] ),
                                             port:port );
}

exit( 0 );
