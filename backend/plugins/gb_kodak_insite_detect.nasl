###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodak_insite_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Kodak inSite Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106820");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 16:58:14 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kodak inSite Detection");

  script_tag(name:"summary", value:"Detection of Kodak inSite.

The script sends a connection request to the server and attempts to detect Kodak inSite and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.kodak.com/US/en/prinergy-workflow/platform/insite-prepress-portal/default.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = '/Site/Pages/login.aspx';
res = http_get_cache(port: port, item: url);

if ("Kodak InSite" >< res && "CSWStyle_PoweredBy" >< res && "kstrLoginPageURL" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "&amp;Version=([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kodak_insite/version", value: version);
  }

  set_kb_item(name: "kodak_insite/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kodak:insite:");
  if (!cpe)
    cpe = 'cpe:/a:kodak:insite';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Kodak InSite", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
