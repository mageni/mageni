# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140184");
  script_version("2021-11-23T14:13:02+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-03-14 14:06:33 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dahua Devices Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Dahua Devices (DVR/NVR/IPC) and their
  OEMs.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("cpe.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );
# nb: The devices doesn't provide a "Server:" banner. This check should prevent some possible
# false detection for other unrelated devices / vendors.
if( ! banner || egrep( string:banner, pattern:"^Server\s*:.+", icase:TRUE ) )
  exit( 0 );

buf = http_get_cache( port:port, item:"/" );

if( ( "<title>WEB SERVICE</title>" >< buf && "ui-dialog-content" >< buf ) ||
    ( "@WebVersion@" >< buf && "t_username" >< buf && ">Login<" >< buf ) ||
    ( "ui-video-wrap-icon" >< buf && "t_username" >< buf && "slct_userType" >< buf ) ||
    ( '"method":"global.login"' >< buf && "/RPC2_Login" >< buf ) ) {
  version = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:"/", url_only:TRUE );
  cpe = "cpe:/a:dahua:nvr:";

  set_kb_item( name:"dahua/device/detected", value:TRUE );
  set_kb_item( name:"dahua/device/http/detected", value:TRUE );

  os_register_and_report( os:"Linux/Unix (Embedded)", cpe:"cpe:/o:linux:kernel",
                          banner_type:"Dahua Web Service", port:port, desc:"Dahua Devices Detection (HTTP)",
                          runs_key:"unixoide" );

  register_and_report_cpe( app:"Dahua Web Service",
                           ver:version,
                           base:cpe,
                           expr:"^([0-9.]+)",
                           insloc:"/",
                           regPort:port,
                           conclUrl:conclUrl,
                           extra:"The remote host seems to be using Dahua software (for DVR/NVR/IPC) or a derivative of such." );
}

exit( 0 );