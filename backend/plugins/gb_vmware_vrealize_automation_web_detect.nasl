###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vrealize_automation_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# VMware vRealize Automation Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105863");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-11 17:10:02 +0200 (Thu, 11 Aug 2016)");
  script_name("VMware vRealize Automation Detection");

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

port = get_http_port( default:443 );

buf = http_get_cache( port:port, item:"/" );

if( "title>VMware vRealize Automation" >!< buf || ">VMware<" >!< buf || "vRealize Automation console" >!< buf ) exit( 0 );

set_kb_item( name:"vmware/vrealize/automation/installed", value:TRUE );
vers = 'unknown';
rep_vers = vers;

cpe = 'cpe:/a:vmware:vrealize_automation';

# VMware vRealize Automation Appliance 6.2.1.0-2553372<br/>
v_b = eregmatch( pattern:'VMware vRealize Automation( Appliance)? ([0-9.]+)-([0-9]+)', string:buf );

# VMware vRealize Automation Appliance version 7.0.1.100 (build 3621464)<br/>
if( isnull( v_b ) )
    v_b = eregmatch( pattern:'VMware vRealize Automation( Appliance)? version ([0-9.]+) \\(build ([0-9]+)\\)', string:buf );

if( ! isnull( v_b[2] ) )
{
  vers = v_b[2];
  rep_vers = vers;
  set_kb_item( name:"vmware/vrealize/automation/version", value:vers );
  cpe += ':' + vers;
}

if(  ! isnull( v_b[3] ) )
{
  build = v_b[3];
  rep_vers += ' (Build: ' + build + ')';
  set_kb_item( name:"vmware/vrealize/automation/build", value:build );
}

register_product( cpe:cpe, location:"/", port:port, service:'www' );

report = build_detection_report( app:"VMware vRealize Automation", version:rep_vers, install:"/", cpe:cpe, concluded:v_b[0]);
log_message( port:port, data:report );

exit( 0 );



