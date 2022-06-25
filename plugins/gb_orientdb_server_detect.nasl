###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orientdb_server_detect.nasl 55846 2016-08-08 15:37:50 +0530 Aug$
#
# OrientDB Server Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808753");
  script_version("$Revision: 11021 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 15:37:50 +0530 (Mon, 08 Aug 2016)");
  script_name("OrientDB Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2480);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of OrientDB Server.

  This script sends HTTP GET request and try to ensure the presence of
  OrientDB Server from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default: 2480);
host = http_host_name(dont_add_port: TRUE);
found = FALSE;
version = "unknown";
banner = get_http_banner(port: port);

if ("OrientDB Server" >< banner) {
  found = TRUE;

  if(vers = eregmatch(pattern: "OrientDB Server v.([0-9.]+)", string: banner))
    version = vers[1];
}

# Application not yet confirmed or version still unknown
if (!found || version == "unknown") {
  buf = http_get_cache(port: port, item: "/server/version");

  if (buf =~ "^HTTP/1\.[01] 200" && "OrientDB Server" >< buf)
    found = TRUE;

  if (vers = eregmatch(pattern: "([0-9.]+)$", string: buf)) {
    version = vers[1];
    concUrl = report_vuln_url(port: port, url: "/server/version", url_only: TRUE);
  }
}

if (found) {
  buf = http_get_cache(item:"/listDatabases", port:port);

  if (dbs = eregmatch(pattern: '"databases":\\[(.*)\\]', string: buf)) {
    databases = split(dbs[1],sep:",", keep:FALSE);
    set_kb_item(name: "OrientDB/" + host + "/" + port + "/databases", value: dbs[1]);

    extra = 'The following databases were found on the OrientDB Server:\n';

    foreach database(databases) {
      database = str_replace(string: database, find: '"', replace: '');
      extra += '- ' + database + '\n';
      url = "/database/" + database;

      req = http_get_req(port: port,
                         url: url,
                         accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
      res = http_keepalive_send_recv(port: port, data: req);

      if ('"code": 401' >< res && '"reason": "Unauthorized"' >< res &&  '"content": "401 Unauthorized."' >< res) {
        set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url);
        set_kb_item(name: "www/content/auth_required", value: TRUE);
        set_kb_item(name: "www/" + host + "/" + port + "/OrientDB/auth_required", value: url);
        set_kb_item(name: "OrientDB/auth_required", value: TRUE );
      }
    }
  }

  set_kb_item(name: "OrientDB/Installed", value: TRUE);
  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:orientdb:orientdb:");

  if (!cpe)
    cpe = 'cpe:/a:orientdb:orientdb';

  register_product(cpe: cpe, location: "/", port: port);
  log_message(data: build_detection_report(app: "OrientDB Server",
                                           version: version,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: vers[0],
                                           concludedUrl: concUrl,
                                           extra: extra),
                                           port: port);
  exit(0);
}
