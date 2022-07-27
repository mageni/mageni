###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_netvault_backup_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Dell/Quest NetVault Backup Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.805652");
  script_version("$Revision: 10908 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell/Quest NetVault Backup Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Dell/Quest Netvault Backup.

  This script sends HTTP GET request and try to get the version from the response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.quest.com/products/netvault-backup/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = http_get_cache(item: "/", port: port);

if ("<title>NetVault Backup</title>" >< res && "serversummarypage.js" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "Server:( NetVault/)?([0-9.]+)", string: res);
  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name:"dell/netvaultbackup/installed", value:TRUE);

  cpe = build_cpe(value: version, exp: "([0-9.]+)", base: "cpe:/a:dell:netvault_backup:");
  if (!cpe)
    cpe = "cpe:/a:dell:netvault_backup";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Dell/Quest NetVault Backup", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
