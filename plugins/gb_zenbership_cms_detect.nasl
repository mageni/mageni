###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenbership_cms_detect.nasl 10821 2018-08-07 14:52:02Z cfischer $
#
# Zenbership CMS Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107220");
  script_version("$Revision: 10821 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 16:52:02 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Zenbership CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Zenbership CMS.

  The script sends an HTTP request to the server and attempts to detect the application from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port(default: 80);
if (!can_host_php(port: appPort)) exit(0);

rootInstalled = FALSE;

foreach dir (make_list_unique("/", "/zenbership", "/membership", "/member", "/zen", "/zenbership-master", cgi_dirs(port: appPort))) {

  if (rootInstalled) break;

  install = dir;
  if (dir == "/") dir = "";

  url = dir +  "/admin/login.php";

  rcvRes = http_get_cache(item: url, port: appPort);

  if (rcvRes =~ "^HTTP/1\.[01] 200" && "<title>Welcome to Zenbership" >< rcvRes &&
      ('content="Zenbership Membership Software"' >< rcvRes || 'a href="http://documentation.zenbership.com/"' >< rcvRes)) {

    if (dir == "" ) rootInstalled = TRUE;
    vers = 'unknown';

    tmpVer = eregmatch(pattern: ">v([0-9a-z]+)",
                   string: rcvRes);

    if (tmpVer[1]) {
      vers = tmpVer[1];
    }

    set_kb_item(name: "zenbership/installed", value: TRUE);
    set_kb_item(name: "zenbership/version", value: vers);

    cpe = build_cpe(value: vers, exp: "^([0-9a-z]+)", base: "cpe:/a:castlamp:zenbership:");

    if (!cpe)
      cpe = 'cpe:/a:castlamp:zenbership';

    register_product(cpe: cpe, location: install, port: appPort, service: "www");

    log_message(data:build_detection_report(app: "Zenbership",
                                            version: vers,
                                            install: install,
                                            cpe: cpe,
                                            concluded: tmpVer[0]),
                                            port: appPort);
  }
}

exit(0);
