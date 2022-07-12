###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_media_server_detect.nasl 12930 2019-01-03 16:22:18Z cfischer $
#
# Logitech SqueezeCenter/Media Server Detection (HTTP)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811877");
  script_version("$Revision: 12930 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 17:22:18 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-10-24 17:24:40 +0530 (Tue, 24 Oct 2017)");
  script_name("Logitech SqueezeCenter/Media Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("LogitechMediaServer/banner");

  script_tag(name:"summary", value:"Detection of a Logitech SqueezeCenter/Media Server.

  This script sends a HTTP GET request to the target and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port(default:9000);
banner = get_http_banner(port:port);

if(_banner = egrep(string:banner, pattern:"^Server: Logitech Media Server", icase:TRUE)) {

  _banner = chomp(_banner);

  version = "unknown";

  # Server: Logitech Media Server (7.7.2 - 33893)
  ver = eregmatch(pattern:'Server: Logitech Media Server \\(([0-9.]+)[^)]*\\)', string:_banner);
  if(ver[1])
    version = ver[1];

  set_kb_item(name:"logitech/squeezecenter/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/port", value:port );
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/detected", value:TRUE);
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/version", value:version);
  set_kb_item(name:"logitech/squeezecenter/http/" + port + "/concluded", value:_banner);
}

exit(0);
