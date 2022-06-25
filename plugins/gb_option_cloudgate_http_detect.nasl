###############################################################################
# OpenVAS Vulnerability Test
#
# Option CloudGate Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808245");
  script_version("2020-06-17T11:26:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-18 10:16:17 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2016-07-04 17:44:06 +0530 (Mon, 04 Jul 2016)");

  script_name("Option CloudGate Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Option CloudGate devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port(default: 80);

res = http_get_cache(item: "/", port: port);

if(("<title>CloudGate</title>" >< res && "Powered by Cloudgate" >< res && "js/cg.js" >< res) ||
   ('document.title = "CloudGate"' >< res && "api/replacementui" >< res)) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "option/cloudgate/detected", value: TRUE);
  set_kb_item(name: "option/cloudgate/http/port", value: port);
  set_kb_item(name: "option/cloudgate/http/" + port + "/version", value: version);
  set_kb_item(name: "option/cloudgate/http/" + port + "/model", value: model);
}

exit(0);
