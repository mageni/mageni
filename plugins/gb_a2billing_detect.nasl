###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a2billing_detect.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# A2billing Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107236");
  script_version("$Revision: 11396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 16:22:38 +0700 (Fri, 08 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("A2billing Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.asterisk2billing.org/");

  script_tag(name:"summary", value:"Detection of A2billing.

  The script sends a connection request to the server and attempts to detect A2billing and to
  extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);
rootInstalled = FALSE;

foreach dir (make_list_unique("/", "/admin", "/admin/Public", "/Public", "/a2billing", "/a2billing/Public",
                              "/a2billing/admin/Public", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/") dir = "";
  if (rootInstalled) break;

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  if (res =~ "^HTTP/1\.[01] 200" && "<title>..:: A2Billing Portal ::..</title>" >< res) {

    if (install == "/") rootInstalled = TRUE;

    version = "unknown";
    ver = eregmatch( pattern: 'A2Billing v([0-9.]+) is a <a href="', string: res);

    if (!isnull(ver[1])) {
      version = ver[1];
      set_kb_item(name: "a2billing/version", value: version);
    }

    set_kb_item(name: "a2billing/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:a2billing:a2billing:");
    if (!cpe)
      cpe = 'cpe:/a:a2billing:a2billing';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "A2billing", version: version, install: install,
                                           cpe: cpe, concluded: ver[0]),
                port: port);
  }
}

exit(0);
