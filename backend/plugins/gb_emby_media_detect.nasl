###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emby_media_detect.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Emby Media Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107098");
  script_version("$Revision: 10017 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2017-05-02 14:04:20 +0200 (Tue, 02 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Emby Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8096);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Emby Media Server.

The script sends a connection request to the server and attempts to detect Emby Media Server and to
extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port(default: 8096);
url = '/web/login.html';

res = http_get_cache(port: appPort, item: url);

if ("<title>Emby</title>" >< res && "Energize your media" >< res && "emby-input" >< res)
{
    tmpVer = eregmatch(pattern: "\.js\?v=([0-9.]+)", string: res);
    if(!isnull(tmpVer[1])) {
      version = tmpVer[1];
      set_kb_item(name: "emby_media_server/version", value: version);
    }

    set_kb_item( name:"emby_media_server/installed", value:TRUE );

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:emby:media:");
    if (!cpe)
      cpe = 'cpe:/a:emby:media';

    register_product(cpe: cpe, location: "/", port: appPort);

    log_message( data:build_detection_report(app:"Emby Media Server", version: version, install: "/",
                                             cpe:cpe, concluded: tmpVer[0]),
                 port:appPort);

    exit( 0 );
}

exit(0);
