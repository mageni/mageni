###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_accellion_fta_detect.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# Accellion FTA Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106030");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2015-07-28 09:48:42 +0700 (Tue, 28 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Accellion FTA Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Accellion File Transfer Appliance

  The script sends a connection request to the server and attempts to detect Accellion File Transfer
  Appliances.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 443);

foreach dir (make_list_unique("/courier", cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache( item:url, port:port );

  if( "you can manage your application settings," >< res && "Accellion Corporate" >< res ) {
    version = "unknown";

    vers = eregmatch(string: res, pattern: "<span>FTA([.0-9]+)( \([A-Z]{2}\))?</span>", icase: TRUE);
    if (!isnull(vers[1])) {
      version = chomp(vers[1]);
      set_kb_item(name: "accellion_fta/version", value: version);
    }
    else {
      req = http_get(port: port, item: dir + '/web/1000@/wmLogin.html?');
      res = http_keepalive_send_recv(port: port, data: req);
      vers = eregmatch(pattern: "js/coreUtils.js\?([0-9_]+)", string: res);
      if (!isnull(vers[1])) {
        v = split(vers[1] , sep: "_", keep: FALSE);
        version = v[0] + "."+ substr(v[1], 0, 1) + "." + substr(v[1], 2);
        set_kb_item(name: "accellion_fta/version", value: version);
      }
    }

    set_kb_item(name: "accellion_fta/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base:"cpe:/h:accellion:secure_file_transfer_appliance:");
    if (!cpe)
      cpe = 'cpe:/h:accellion:secure_file_transfer_appliance';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app:"Accellion FTA", version: version, install: install, cpe:cpe,
                                             concluded:vers[0]),
                port:port);
    exit(0);
  }
}

exit(0);
