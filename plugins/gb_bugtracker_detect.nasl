###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugtracker_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# BugTracker.NET Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801278");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BugTracker.NET Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of BugTracker.NET on remote host
  and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/btnet", "/bugtracker", "/bugtrackernet", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/about.html", port:port );
  rcvRes2 = http_get_cache( item: dir + "/default.aspx", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" && ">BugTracker.NET<" >< rcvRes ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && ">BugTracker.NET<" >< rcvRes &&
        '"Logon"' >< rcvRes2 && ">User:<" >< rcvRes2 && ">Password:<" >< rcvRes2 ) ) {

    version = "unknown";

    ver = eregmatch( pattern:'Version ([0-9.]+)', string:rcvRes );
    if( ! isnull( ver[1] ) ) version = ver[1];

    ## BugTracker.NET 3.4.4 showing its version as 3.4.3
    tmp_version = version +" under "+ install;
    set_kb_item( name:"www/" + port + "/btnet", value:tmp_version );
    set_kb_item( name:"BugTrackerNET/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ifdefined:bugtracker.net:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ifdefined:bugtracker.net';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"BugTracker.NET",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );