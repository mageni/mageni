###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_performance_insight_detect.nasl 10929 2018-08-11 11:39:44Z cfischer $
#
# HP Performance Insight Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103059");
  script_version("$Revision: 10929 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 13:39:44 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-02-03 16:40:04 +0100 (Thu, 03 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HP Performance Insight Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-119^1211_4000_100__");

  script_tag(name:"summary", value:"This host is running the HP OpenView Performance Insight Web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8080 );

buf = http_get_cache( item:"/", port:port );
if( isnull( buf ) ) exit( 0 );

if( ( "<h1>HP Performance Insight" >< buf || "HP OpenView Performance Insight Login" >< buf ) && "Hewlett-Packard" >< buf ) {

  install = "/";
  vers = "unknown";

  version = eregmatch( string:buf, pattern:"<h4>Version ([^<]+)<", icase:TRUE );
  if( ! isnull( version[1] ) ) vers = chomp( version[1] );

  tmp_version = vers + " under " + install;
  set_kb_item( name:"www/" + port + "/hp_openview_insight", value:tmp_version );
  set_kb_item( name:"hp_openview_insight/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"([0-9.]+)", base:"cpe:/a:hp:openview_performance_insight:");
  if( isnull( cpe ) )
    cpe = "cpe:/a:hp:openview_performance_insight";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"HP OpenView Performance Insight",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:port );
}

exit( 0 );
