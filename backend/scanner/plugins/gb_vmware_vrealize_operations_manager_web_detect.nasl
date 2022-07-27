###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_operations_manager_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMware vRealize Operations Manager Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105862");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-11 15:53:38 +0200 (Thu, 11 Aug 2016)");
  script_name("VMware vRealize Operations Manager Detection");

  script_tag(name:"summary", value:"This Script performs HTTP based detection of VMware vRealize Operations Manager");

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

port = get_http_port( default:443 );

url = '/admin/login.action';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>vRealize Operations Manager" >< buf )
{
  api_url = '/suite-api/api/versions/current';
  req = http_get( item:api_url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "ops:version" >!< buf || "VMware vRealize Operations Manager" >!< buf ) exit( 0 );

  cpe = 'cpe:/a:vmware:vrealize_operations_manager';
  vers = 'unknown';
  rep_vers = vers;

  set_kb_item( name:"vmware/vrealize/operations_manager/installed", value:TRUE );

  # <ops:releaseName>VMware vRealize Operations Manager 6.1.0</ops:releaseName>
  version = eregmatch( pattern:'<ops:releaseName>VMware vRealize Operations Manager ([0-9.]+[^<]+)</ops:releaseName>', string:buf );
  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    rep_vers = vers;
    cpe += ':' + vers;
    set_kb_item( name:"vmware/vrealize/operations_manager/version", value:vers );
  }

  # <ops:buildNumber>3038036</ops:buildNumber>
  b = eregmatch( pattern:'<ops:buildNumber>([0-9]+[^<]+)</ops:buildNumber>', string:buf );
  if( ! isnull( b[1] ) )
  {
    build = b[1];
    rep_vers += ' (Build: ' + build + ')';
    set_kb_item( name:"vmware/vrealize/operations_manager/build", value:build );
  }

  register_product( cpe:cpe, location:'/', port:port, service:'www' );

  report = build_detection_report( app:"VMware vRealize Operations Manager", version:rep_vers, install:"/", cpe:cpe, concluded:version[0], concludedUrl:api_url);
  log_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );


