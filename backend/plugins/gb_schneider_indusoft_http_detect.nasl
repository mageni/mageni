###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_indusoft_http_detect.nasl 14057 2019-03-08 13:02:00Z jschulte $
#
# Schneider Electric InduSoft Web Studio Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141011");
  script_version("2019-04-11T08:41:23+0000");
  script_tag(name:"last_modification", value:"2019-04-11 08:41:23 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-04-19 13:02:45 +0700 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric InduSoft Web Studio Detection");

  script_tag(name:"summary", value:"Detection of Schneider Electric InduSoft Web Studio.

  The script sends a connection request to the server and attempts to detect Schneider Electric InduSoft Web Studio
  and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 81, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.indusoft.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("ISSymbol1.ProductName" >< res && "InduSoft Web Studio" >< res) {
  set_kb_item(name: "schneider_indusoft/installed", value: TRUE);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/detected", value: TRUE);

  version = "unknown";
  concluded = "HTTP Request";

  vers = eregmatch(pattern: 'ProductVersion = "([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = vers[0];
  }

  set_kb_item(name: "schneider_indusoft/http/" + port + "/version", value: version);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/concluded", value: vers[0]);
  set_kb_item(name: "schneider_indusoft/http/" + port + "/location", value: "/");
  set_kb_item(name: "schneider_indusoft/http/port", value: port);
}

exit(0);