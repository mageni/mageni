###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nec_communication_platforms_detect.nasl 12643 2018-12-04 09:55:30Z ckuersteiner $
#
# NEC Communication Platforms Devices Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112309");

  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_version("$Revision: 12643 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 10:55:30 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-06-21 12:10:11 +0200 (Thu, 21 Jun 2018)");

  script_name("NEC Communication Platforms Devices Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8001);
  script_exclude_keys("Settings/disable_cgi_scanning");


  script_tag(name:"summary", value:"Detection of NEC Communication Platforms Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is an NEC device from the reply.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

fingerprint["5ccacccda165a52ed35631cd1560173c"] = "SL1100";
fingerprint["8ff960ae800da220d5ddd499610236c6"] = "SV8100";
fingerprint["56fbf5a1166d69e1bb3b703962b280ac"] = "SV9100";
fingerprint["7c1b1fb135e268a230c13a373b2859cf"] = "UX5000";

port = get_http_port(default:80);

foreach dir ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  file = "/";
  url = dir + file;

  res = http_get_cache( item: url, port: port );

  if( res =~ 'Server: Henry/1\\.1' && '<title>WebPro</title>' >< res &&
      '<frame name="banFrm" src=\'Banner.htm\'' >< res && '<frame name="mainFrm" src=\'Login.htm\' />' >< res ) {

    set_kb_item( name: "nec/communication_platforms/detected", value: TRUE );

    model = "unknown";
    version = "unknown";

    images = make_list( "Images/Draco/PHILIPS/SL1100.PNG",
                        "Images/UniCorn/appTitle.png",
                        "Images/Cygnus/GE/appTitle.png",
                        "Images/Cygnus/US/appTitle.png",
                        "Images/Cygnus/PHILIPS/appTitle.png",
                        "Images/Cygnus/NA/appTitle.png" );

    foreach image ( images ) {
      req = http_get( port:port, item:url + image );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      if( ! isnull( res  ) ) {
        md5 = hexstr( MD5( res ) );
        if( fingerprint[md5] ) {
          model = fingerprint[md5];
          break;
        }
      }
    }

    version_url = url + "Login.htm";
    res = http_get_cache( item: version_url, port: port );
    version_match = eregmatch( pattern: '<br />([0-9.]+)</td>', string: res );

    if ( version_match[1] ) {
      version = version_match[1];
      concluded_url = report_vuln_url( port:port, url:version_url, url_only:TRUE );
    }

    set_kb_item( name:"nec/communication_platforms/model", value:model );
    set_kb_item( name:"nec/communication_platforms/version", value:version );

    base = "cpe:/o:nec:communication_platforms_" + tolower(model);
    app = "NEC Communication Platforms";

    os_cpe = build_cpe( value:version, exp:"([0-9.]+)", base:base + ":" );
    if( ! os_cpe )
      os_cpe = base;

    register_and_report_os( os:app, cpe:os_cpe, banner_type:"HTTP Login Page", port:port,
                            desc:"NEC Communication Platforms Devices Detection", runs_key:"unixoide" );
    register_and_report_cpe( app:app, ver:version, concluded:version_match[0], cpename:os_cpe, insloc:install,
                             regPort:port, conclUrl:concluded_url );

    exit(0);
  }
}

exit(0);
