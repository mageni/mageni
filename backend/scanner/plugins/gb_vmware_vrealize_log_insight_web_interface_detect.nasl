###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_log_insight_web_interface_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMware vRealize Log Insight Webinterface Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105753");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 12:33:05 +0200 (Fri, 10 Jun 2016)");
  script_name("VMware vRealize Log Insight Webinterface Detection");

  script_tag(name:"summary", value:"This script detects the VMware vRealize Log Insight Webinterface");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gather-package-list.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

url = "/login";
buf = http_get_cache( port:port, item:url );

if( "<title>vRealize Log Insight - Login</title>" >!< buf ) exit( 0 );

cpe = 'cpe:/a:vmware:vrealize_log_insight';
set_kb_item( name:"vmware/vrealize_log_insight/webinterface/detected", value:TRUE );

url = '/api/v1/version';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( '"releaseName"' >< buf )
{
  v_b = eregmatch( pattern:'"version":"([0-9.]+)-([0-9]+)"', string:buf );
  if( ! isnull( v_b[1] ) )
  {
    version = v_b[1];
    cpe += ':' + version;
    set_kb_item( name:"vmware/vrealize_log_insight/www/version", value:version );
  }

  if( ! isnull( v_b[2] ) )
  {
    build = v_b[2];
    set_kb_item( name:"vmware/vrealize_log_insight/www/version", value:build );
  }
}

if( ! get_kb_item( "vmware/vrealize_log_insight/rls" ) )
  set_kb_item( name:"vmware/vrealize_log_insight/rls", value:'VMware vRealize Log Insight ' + version + ' Build ' + build + '\n ds:www' );

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = 'The VMware vRealize Log Insight Webinterface is running at this port.\nCPE: ' + cpe;
if( build ) report += '\nBuild: ' + build;

log_message( port:port, data:report );
exit( 0 );

