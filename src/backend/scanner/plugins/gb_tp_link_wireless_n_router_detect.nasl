###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_wireless_n_router_detect.nasl 11157 2018-08-29 09:26:15Z jschulte $
#
# TP-Link Wireless Router Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811880");
  script_version("$Revision: 11157 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-29 11:26:15 +0200 (Wed, 29 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 14:30:38 +0530 (Wed, 25 Oct 2017)");
  script_name("TP-Link Wireless Router Detection");

  script_tag(name:"summary", value:"Detection of TP-Link Wireless Router.

  The script sends a connection request to the server and attempts to
  detect the presence and get the model of TP-Link Wireless Router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");

tlPort = get_http_port(default:8080);

banner = get_http_banner(port:tlPort);
if(banner && banner =~ 'WWW-Authenticate: Basic realm="TP-LINK Wireless.*Router')
{
  location = "/";
  version = "Unknown";

  set_kb_item(name:"TP-LINK/Wireless/Router/detected", value: TRUE);

  model = eregmatch(pattern:'TP-LINK Wireless.*Router ([A-Z0-9-]+)', string:banner);
  if(model[1]){
    set_kb_item(name:"TP-LINK/Wireless/Router/model", value: model[1]);
  }

  cpe = "cpe:/h:tp-link:wireless-n_router";

  register_product(cpe:cpe, location:location, port:tlPort);

  log_message(data: build_detection_report(app: "TP-LINK Wireless Wireless Router",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: "TP-LINK Wireless Router " + model[1]),
                                           port: tlPort);
  exit(0);
}
