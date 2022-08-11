###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sync_breeze_enterprise_detect.nasl 12813 2018-12-18 07:43:29Z ckuersteiner $
#
# Flexense SyncBreeze Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809058");
  script_version("$Revision: 12813 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 08:43:29 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Flexense SyncBreeze Detection");

  script_tag(name:"summary", value:"Detection of Flexense SyncBreeze.

The script sends a connection request to the server and attempts to detect Flexense SyncBreeze and to extract its
version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/login", port:port);

if(">Sync Breeze Enterprise" >< res && ">User Name" >< res && ">Password" >< res) {
  version = "unknown";

  syncVer = eregmatch(pattern:">Sync Breeze Enterprise v([0-9.]+)", string:res);
  if (syncVer[1])
    version = syncVer[1];

  set_kb_item(name:"flexsense_syncbreeze/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:flexense:syncbreeze:");
  if(!cpe)
    cpe = "cpe:/a:flexense:syncbreeze";

  register_product(cpe:cpe, location:"/", port:port);

  log_message(data: build_detection_report(app: "Flexsense Sync Breeze Enterprise", version: version,
                                           install: "/", cpe: cpe, concluded:syncVer),
              port:port);
  exit(0);
}

exit(0);
