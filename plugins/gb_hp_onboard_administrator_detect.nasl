###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_onboard_administrator_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# HP Onboard Administrator Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103794");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-01 10:46:38 +0200 (Tue, 01 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("HP Onboard Administrator Detection");

  script_tag(name:"summary", value:"Detection of HP Onboard Administrator.

The script sends a connection request to the server and attempts to detect HP Onboard Administrator and to extract
its version.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

url = '/xmldata?item=All';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "<PN>.*Onboard Administrator.*</PN>" || "<FWRI>" >!< buf)
  exit(0);

vers = 'unknown';

version = eregmatch(pattern:"<FWRI>([^<]+)</FWRI>", string:buf);
if(!isnull(version[1])) {
  vers = version[1];
  set_kb_item(name: "hp_onboard_admin/version", value: vers);
}

set_kb_item(name:"hp_onboard_admin/installed",value:TRUE);

cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:hp:onboard_administrator:");
if(isnull(cpe))
  cpe = 'cpe:/a:hp:onboard_administrator';

register_product(cpe:cpe, location:"/", port:port);

log_message(data: build_detection_report(app:"HP Onboard Administrator",version:vers,install:"/", cpe:cpe,
                  concluded: version[0], concludedUrl: url),
            port:port);
exit(0);

