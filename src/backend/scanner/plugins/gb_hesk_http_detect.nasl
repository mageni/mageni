# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148819");
  script_version("2022-10-11T10:12:36+0000");
  script_tag(name:"last_modification", value:"2022-10-11 10:12:36 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-05 09:17:16 +0000 (Wed, 05 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HESK Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HESK.");

  script_xref(name:"URL", value:"https://www.hesk.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/hesk", "/help", "/helpdesk", "/ticket", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache(port: port, item: url);

  if ((">Help Desk Software<" >< res && 'www.hesk.com"' >< res && res =~ ">View existing tickets?<") ||
      # <p class="text-center">Powered by <a href="https://www.hesk.com" class="link">Help Desk Software</a> <span class="font-weight-bold">HESK</span>
      # <span class="smaller">&nbsp;<br />Powered by <a href="https://www.hesk.com" class="smaller" title="Free PHP Help Desk Software">Help Desk Software</a> <b>HESK</b>
      # <p class="text-center">Powered by <a href="https://www.hesk.com" class="link">Help Desk Software</a> <span class="font-weight-bold">HESK</span><br>More IT firepower? Try <a href="https://www.sysaid.com
      # nb: An old VT had the pattern if('>Powered by <' >< res && '> HESK&' >< res)
      (">Powered by <" >< res && egrep(string: res, pattern: "(> HESK&|>HESK<)", icase: FALSE))
     ) {
    version = "unknown";

    # theme/hesk3/customer/js/hesk_functions.js?3.3.2
    # type="text/javascript" src="./hesk_javascript.js?2.7.2"></script>
    vers = eregmatch(pattern: "/hesk_[^.]+\.js\?([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "hesk/detected", value: TRUE);
    set_kb_item(name: "hesk/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hesk:hesk:");
    if (!cpe)
      cpe = "cpe:/a:hesk:hesk";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "HESK", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
