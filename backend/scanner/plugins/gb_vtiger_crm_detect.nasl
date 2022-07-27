###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtiger_crm_detect.nasl 12926 2019-01-03 03:38:48Z ckuersteiner $
#
# vtiger CRM Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100909");
  script_version("$Revision: 12926 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 04:38:48 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-11-18 13:10:44 +0100 (Thu, 18 Nov 2010)");
  script_name("vtiger CRM Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8888);

  script_tag(name:"summary", value:"Detection of Symantec vtiger CRM.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/vtigercrm", "/crm", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( ( "<title>vtiger CRM" >< buf && ( "login_language" >< buf || ">Powered by vtiger" >< buf ) ) ||
      ( "<title>Vtiger" >< buf && "Powered by vtiger CRM" >< buf ) ||
      ("Powered by vtiger CRM" >< buf && 'target="_blank">Privacy Policy</a>' >< buf ) ) {

    version = "unknown";

    ver = eregmatch( string:buf, pattern:"vtiger CRM[\ ]?+[-]?[\ ]?+([0-9.]+)([^ ]| RC)", icase:TRUE );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    set_kb_item( name:"vtiger/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vtiger:vtiger_crm:" );
    if( ! cpe )
      cpe = 'cpe:/a:vtiger:vtiger_crm';

    register_product( cpe:cpe, location:install, port:port, service: "www" );

    log_message( data:build_detection_report( app:"vtiger CRM", version:version, install:install, cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
