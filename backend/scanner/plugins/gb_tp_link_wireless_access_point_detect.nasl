###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_wireless_access_point_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# TP-Link Wireless Access Point Detection
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107331");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-16 14:32:15 +0200 (Mon, 16 Jul 2018)");
  script_name("TP-Link Wireless Access Point Detection");

  script_tag(name:"summary", value:"Detection of TP-Link Wireless Access Point.

  The script sends a connection request to the server and attempts to
  detect the presence and get the model of TP-Link Wireless Access Point.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

tlPort = get_http_port(default:80);
banner = get_http_banner(port:tlPort);

if(banner && banner =~ 'WWW-Authenticate: Basic realm="TP-LINK Wireless N Access Point.*')
{
  location = "/";
  version = "Unknown";

  set_kb_item(name:"TP-LINK/Wireless/Access Point/detected", value: TRUE);

  model = eregmatch(pattern:'TP-LINK Wireless N Access Point ([A-Z0-9-]+)', string:banner);
  if(model[1]){
    set_kb_item(name:"TP-LINK/Wireless/Access Point/model", value: model[1]);
  }

  ## Created new cpe
  cpe = "cpe:/h:tp-link:wireless-n_access_point";

  register_product(cpe:cpe, location:location, port:tlPort);

  log_message(data: build_detection_report(app: "TP-LINK Wireless Wireless Access Point",
                                           version: version,
                                           install: location,
                                           cpe: cpe,
                                           concluded: "TP-LINK Wireless Access Point " +model[1]),
                                           port: tlPort);
  exit(0);
}
