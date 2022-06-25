###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orange_livebox_router_detect.nasl 12888 2018-12-27 18:16:07Z tpassfeld $
#
# Orange Livebox Router Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114053");
  script_version("$Revision: 12888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-27 19:16:07 +0100 (Thu, 27 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-27 16:40:02 +0100 (Thu, 27 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Orange Livebox Router Detection");

  script_tag(name:"summary", value:"Detection of Orange Livebox router.

  The script sends a connection request to the server and attempts to detect the web interface for Orange's Livebox router.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.arcadyan.com/home.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

url = "/";
res = http_get_cache(port: port, item: url);

if('var company="Arcadyan Inc.";' >< res && 'var help_urlname="www.arcadyan.com/802";' >< res && 'var urlname="www.arcadyan.com";' >< res) {
  version = "unknown";
  model = "unknown";
  install = "/";

  #var firmware_ver='00.96.00.96.609ES';
  ver = eregmatch(pattern: "var firmware_ver='([0-9.A-Za-z]+)';", string: res);
  if(!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "orange/livebox/version", value: version);
  }

  #var product_name="Arcadyan ARV7519";
  mod = eregmatch(pattern: 'var product_name="Arcadyan ([a-zA-Z0-9]+)";', string: res);
  if(!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "orange/livebox/model", value: model);
  }

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  cpe = "cpe:/h:orange:livebox:";

  set_kb_item(name: "orange/livebox/detected", value: TRUE);
  set_kb_item(name: "orange/livebox/" + port + "/detected", value: TRUE);

  register_and_report_cpe(app: "Orange Livebox Router",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.A-Za-z]+)",
                          insloc: install,
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Model: " + model);
}

exit(0);
