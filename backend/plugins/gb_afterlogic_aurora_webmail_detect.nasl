###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_afterlogic_aurora_webmail_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# AfterLogic Aurora/WebMail Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140381");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-20 16:49:11 +0700 (Wed, 20 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AfterLogic Aurora/WebMail Detection");

  script_tag(name:"summary", value:"Detection of AfterLogic Aurora/WebMail.

The script sends a connection request to the server and attempts to detect AfterLogic Aurora/WebMail and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://afterlogic.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/", "/afterlogic", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if (("AfterLogic WebMail" >< res && "var EmptyHtmlUrl" >< res) ||
      ("DemoWebMail" >< res && res =~'SiteName":".*","DefaultLanguage')) {
    version = "unknown";

    req = http_get(port: port, item: dir + "/VERSION");
    ver_res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    vers = eregmatch(pattern: "^([0-9.]+)$", string: ver_res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "afterlogic_aurora_webmail/version", value: version);
      concUrl = dir + "/VERSION";
    }
    else {
      vers = eregmatch(pattern: "<!--([version ]+)?([0-9.]+)( )?-->", string: res);
      if (!isnull(vers[2])) {
        version = vers[2];
        set_kb_item(name: "afterlogic_aurora_webmail/version", value: version);
      }
    }

    set_kb_item(name: "afterlogic_aurora_webmail/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:afterlogic:aurora:");
    if (!cpe)
      cpe = 'cpe:/a:afterlogic:aurora';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "AfterLogic Aurora/WebMail", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
