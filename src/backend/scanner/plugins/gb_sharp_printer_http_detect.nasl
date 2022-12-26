# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103779");
  script_version("2022-12-20T09:52:38+0000");
  script_tag(name:"last_modification", value:"2022-12-20 09:52:38 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-09-02 14:31:24 +0100 (Mon, 02 Sep 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SHARP Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SHARP printer devices.");

  exit(0);
}

include("sharp_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

buf = http_get_cache(item: "/", port: port);

# If updating here please also update check in dont_print_on_printers.nasl
if (!buf || buf !~ "^HTTP/1\.[01] (200|302)" ||
    ("Extend-sharp-setting-status" >!< buf && "Server: Rapid Logic" >!< buf))
  exit(0);

urls = get_sharp_detect_urls();

foreach url (keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  buf = http_get_cache(port: port, item:url);
  if (!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: buf, icase: TRUE)) {
    set_kb_item(name: "sharp/printer/detected", value: TRUE);
    set_kb_item(name: "sharp/printer/http/detected", value: TRUE);
    set_kb_item(name: "sharp/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[1])) {
      model = chomp(match[1]);
      set_kb_item(name: "sharp/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "sharp/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    set_kb_item(name: "sharp/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "sharp/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

exit(0);
