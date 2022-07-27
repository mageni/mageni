###############################################################################
# OpenVAS Vulnerability Test
# $Id: landesk_detect.nasl 13690 2019-02-15 10:51:55Z cfischer $
#
# LANDesk Management Agent Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100328");
  script_version("$Revision: 13690 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:51:55 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LANDesk Management Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports(9595, 9593);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of LANDesk Management Agent");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

host = http_host_name( dont_add_port:TRUE );

# nb: 9595 is plain HTTP, 9593 is HTTPS
foreach port( make_list( 9595, 9593 ) ) {

  if( ! get_port_state( port ) ) continue;
  if( http_get_is_marked_broken( port:port, host:host ) ) continue;

  buf = http_get_cache( item:"/", port:port );
  if( isnull( buf ) ) continue;

  if( concl = egrep( pattern:"LANDesk.*Management Agent</title>", string:buf, icase:TRUE ) ) {
    install = "/";
    version = "unknown";
    set_kb_item( name:"landesk_managament_agent/detected", value:TRUE );

    cpe = "cpe:/a:landesk:landesk_management_suite";
    register_product( cpe:cpe, location:install, port:port );
    register_service( port:port, ipproto:"tcp", proto:"landesk" );

    log_message( data:build_detection_report( app:"LANDesk Management Agent",
                                              version:version,
                                              install:"/",
                                              cpe:cpe,
                                              concluded:concl ),
                                              port:port );
  }
}

exit( 0 );