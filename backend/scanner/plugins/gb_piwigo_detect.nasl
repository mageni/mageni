###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Piwigo Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106436");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-07 15:34:03 +0700 (Wed, 07 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Piwigo Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Piwigo

  The script sends a connection request to the server and attempts to detect the presence of Piwigo and to
  extract its version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);
if (!can_host_php(port: port)) exit(0);

foreach dir (make_list_unique("/", "/piwigo", "/Piwigo", "/photos", cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/") dir = "";

  # Seems Piwigo denies our OpenVAS user-agent
  req = http_get_req(port: port, url: dir + "/index.php",
                     user_agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0");
  res = http_keepalive_send_recv(port: port, data: req);

  if( '<meta name="generator" content="Piwigo' >< res || "<title>Piwigo, Welcome" >< res ||
      ( ">Piwigo<" >< res && ">Login<" >< res ) ) {

    version = 'unknown';

    vers = eregmatch(pattern: "js\?v([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "piwigo/version", value: version);
    }

    set_kb_item(name: "piwigo/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:piwigo:piwigo:");
    if (!cpe)
      cpe = 'cpe:/a:piwigo:piwigo';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "Piwigo", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
  }
}

exit(0);
