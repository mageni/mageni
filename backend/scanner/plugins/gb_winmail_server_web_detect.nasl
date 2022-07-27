###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winmail_server_web_detect.nasl 11468 2018-09-19 09:38:34Z ckuersteiner $
#
# Winmail Server Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141490");
  script_version("$Revision: 11468 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-19 11:38:34 +0200 (Wed, 19 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-19 13:59:48 +0700 (Wed, 19 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Winmail Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Winmail Server Webmail.

The script sends a connection HTTP based request to the server and attempts to detect Winmail Server Webmail and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8080, 6080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.magicwinmail.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 6080);

if (!can_host_php(port: port))
  exit(0);

url = '/admin/index.php';
res = http_get_cache(port: port, item: url);

if ("Powered by Winmail Server" >< res && "Set-Cookie: magicwinmail" >< res) {
  version = "unknown";

  # Winmail Mail Server 5.5.1(Build 1203)
  vers = eregmatch(pattern: "Winmail( Mail)? Server ([0-9.]+)(\(Build ([0-9]+)\))?", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    concUrl= url;

    if (!isnull(vers[4])) {
      extra = 'Build:   ' + vers[4];
      set_kb_item(name: "winmail_server/build", value: vers[4]);
    }
  }

  set_kb_item(name: "winmail_server/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:magicwinmail:winmail_server:");
  if (!cpe)
    cpe= 'cpe:/a:magicwinmail:winmail_server';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Winmail Server Webmail", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
