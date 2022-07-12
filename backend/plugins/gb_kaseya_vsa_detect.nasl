###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaseya_vsa_detect.nasl 13512 2019-02-07 02:04:24Z ckuersteiner $
#
# Kaseya VSA Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106738");
  script_version("$Revision: 13512 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-07 03:04:24 +0100 (Thu, 07 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kaseya VSA Detection");

  script_tag(name:"summary", value:"Detection of Kaseya VSA

The script sends a HTTP connection request to the server and attempts to detect the presence of Kaseya VSA and
to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.kaseya.com/products/vsa");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);
if( ! can_host_asp( port:port ) ) exit( 0 );

# Some need a referer to get the version back
header = make_array("Referer", "https://" + get_host_name() + "/");
req = http_get_req(port: port, url: "/vsapres/web20/core/login.aspx", add_headers: header);
res = http_keepalive_send_recv(port: port, data: req);

if ("logoforLogin.gif" >< res && "/vsapres/js/kaseya/web/bootstrap.js" >< res && "Kaseya" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "System Version.*<span>([0-9.]+)</span>", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  # nb: Patchlevel can be higher than the system version
  patchlevel = eregmatch(pattern: "Patch Level[^<]+<br />[^<]+<span>([0-9.]+)</span>", string: res);
  if (!isnull(patchlevel[1])) {
    set_kb_item(name: "kaseya_vsa/patchlevel", value: patchlevel[1]);
    extra = "Patch Level:  " + patchlevel[1];
  }

  set_kb_item(name: "kaseya_vsa/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kaseya:virtual_system_administrator:");
  if (!cpe)
    cpe = 'cpe:/a:kaseya:virtual_system_administrator';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Kaseya VSA", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}

exit(0);
