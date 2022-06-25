###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netmri_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# NetMRI Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103575");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-25 12:05:19 +0200 (Tue, 25 Sep 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetMRI Detection");

  script_tag(name:"summary", value:"Detection of NetMRI.

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:443);

data = 'mode=LOGIN-FORM';
url = "/netmri/config/userAdmin/login.tdf";

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>NetMRI Login" >< res || "<title>Network Automation Login" >< res) {
  # This probably could be checked with a single eregmatch(), however the correct regex is unclear
  lines = split(res);
  c = 0;

  foreach line(lines) {
    c++;
    vers = 'unknown';
    if ("Version:" >< line) {
       version = eregmatch(pattern: "<td>([^<]+)</td>", string: lines[c]);
       if (!isnull(version[1]))
         vers = version[1];
    }

    set_kb_item(name: string("www/", port, "/netmri"), value: string(vers," under /"));
    set_kb_item(name:"netMRI/detected", value:TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:infoblox:netmri:");
    if (!cpe)
      cpe = 'cpe:/a:infoblox:netmri';

    register_product(cpe: cpe, location: "/", port: port);

    log_message(data: build_detection_report(app: "Infoblox NetMRI", version: vers, install: "/", cpe: cpe,
                                             concluded: version[0]),
                port: port);

    exit(0);
  }
}

exit(0);
