###############################################################################
# OpenVAS Vulnerability Test
# $Id: webmin.nasl 13183 2019-01-21 10:00:12Z ckuersteiner $
#
# Webmin / Usermin Detection
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10757");
  script_version("$Revision: 13183 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 11:00:12 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Webmin / Usermin Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Product detection");
  # nb: Don't add a dependency to http_version.nasl which depends on this NVT.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 10000, 20000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Webmin / Usermin.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 10000);

banner = get_http_banner( port:port );
buf = http_get_cache( item:"/", port:port );

if ((banner && egrep(pattern: "^Server: MiniServ.*", string: banner, icase: TRUE)) || "Login to Webmin" >< buf ) {
  vers = "unknown";

  set_kb_item( name:"usermin_or_webmin/installed", value:TRUE );

  if( "Usermin Server" >< banner ) {
    set_kb_item( name:"usermin/installed", value:TRUE );
    usermin = TRUE;
  } else {
     set_kb_item( name:"webmin/installed", value:TRUE );
     webmin = TRUE;
  }

  vers = eregmatch( pattern:"Server: MiniServ/([0-9]\.[0-9]+)", string:banner );
  if (!isnull(vers[1]))
    version = vers[1];

  if (usermin) {
    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:webmin:usermin:");
    if (!cpe)
      cpe = "cpe:/a:webmin:usermin";

    register_product(cpe: cpe, location: "/", port: port, service: "www");

    log_message(data: build_detection_report(app: "Usermin", version: version, install: "/", cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  } else {
    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:webmin:webmin:");
    if (!cpe)
      cpe = "cpe:/a:webmin:webmin";

    register_product(cpe: cpe, location: "/", port: port, service: "www");

    log_message(data: build_detection_report(app: "Webmin", version: version, install: "/", cpe:cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
