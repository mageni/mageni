###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_riverbed_steelcentral_http_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Riverbed SteelCentral Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105787");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-30 13:36:05 +0200 (Thu, 30 Jun 2016)");
  script_name("Riverbed SteelCentral Detection (HTTP)");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

source = "http";

port = get_http_port( default:443 );

buf = http_get_cache( port:port, item:"/" );

if( "<title>Riverbed Technology, Inc.</title>" >< buf )
{
  url = '/api/common/1.0/info';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE ); # <info device_name="cascade-express-VE" model="SCNE-VE-00470" serial="N/A" sw_version="10.8.7 (release 20160106_1504)">

  if( "device_name" >< buf && "sw_version" >< buf && "model" >< buf )
  {
    set_kb_item( name:"riverbed/SteelCentral/detected", value:TRUE );
    if( "-VE" >< buf ) set_kb_item( name:"riverbed/SteelCentral/is_vm", value:TRUE );
    set_kb_item( name:"riverbed/SteelCentral/http_interface/detected", value:TRUE );

    cpe = 'cpe:/a:riverbed:steelcentral';
    vers = 'unknown';

    report_app = 'Riverbed SteelCentral';
    report_version = '';

    version = eregmatch( pattern:'sw_version="([0-9.]+[^ ("\r\n]+)', string:buf );
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      report_version = vers;
      cpe += ':' + vers;
      set_kb_item( name:"riverbed/SteelCentral/" + source + "/version", value:vers);
    }

    rls = eregmatch( pattern:'sw_version="[0-9.]+ \\(release ([^) ]+)\\)', string:buf );
    if( ! isnull( rls[1] ) )
    {
      release = rls[1];
      report_version += ' (' + release + ')';
      set_kb_item( name:"riverbed/SteelCentral/" + source + "/release", value:release );
    }

    mod = eregmatch( pattern:'model="([^"]+)"', string:buf );
    if( ! isnull( mod[1] ) )
    {
      model = mod[1];
      report_app += ' (' + model + ')';
      set_kb_item( name:"riverbed/SteelCentral/" + source + "/model", value:model );
    }

    register_product( cpe:cpe, location:"/", port:port, service:"www" );
    report = build_detection_report( app:report_app, version:report_version, install:"/", cpe:cpe, concluded:"/api/common/1.0/info" );
    log_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );

