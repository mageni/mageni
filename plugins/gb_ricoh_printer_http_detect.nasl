# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142810");
  script_version("2019-08-29T09:18:53+0000");
  script_tag(name:"last_modification", value:"2019-08-29 09:18:53 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-28 04:38:13 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of RICOH printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

urls = make_array(
  "/machinei.asp?Lang=en-us", 'class="modelName">([^<]+)<',   # class="modelName">SP C250DN</td>
  "/web/guest/en/websys/status/configuration.cgi", ">Model Name<[^:]+:<[^<]+<td nowrap>((Aficio )?[^<]+)"  # >Model Name</td><td nowrap>:</td><td nowrap>Aficio MP C3501</td>
  );

foreach url (keys(urls)) {
  res = http_get_cache(port: port, item: url);

  match = eregmatch(pattern: urls[url], string: res, icase: TRUE);
  if (res =~ "^HTTP/1\.[01] 200" && !isnull(match[1])) {
    model = chomp(match[1]);
    concluded = '\n' + match[0];
    concludedUrl = '\n' + report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "ricoh_printer/detected", value:TRUE);
    set_kb_item(name: "ricoh_printer/http/detected", value:TRUE);
    set_kb_item(name: "ricoh_printer/http/port", value: port);
    set_kb_item(name: "ricoh_printer/http/" + port + "/model", value: model);

    url = "/web/guest/en/websys/status/configuration.cgi";
    res = http_get_cache(port: port, item: url);

    # <td nowrap align="">System</td><td nowrap>:</td><td nowrap>1.16</td>
    vers = eregmatch(pattern: ">System<[^:]+:<[^<]+<td nowrap>([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      set_kb_item(name: "ricoh_printer/http/" + port + "/fw_version", value: vers[1]);
      concluded += '\n' + vers[0];
      if (url >!< concludedUrl)
        concludedUrl += '\n' + report_vuln_url(port: port, url: url, url_only: TRUE);
    }
    else {
      url = "/machinei.asp?Lang=en-us";
      res = http_get_cache(port: port, item: url);

      # >Firmware Version</td><td><span class="style1">:</span></td><td nowrap width="100%" >V1.04</td>
      vers = eregmatch(pattern: "Firmware Version</td>[^V]+V([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        set_kb_item(name: "ricoh_printer/http/" + port + "/fw_version", value: vers[1]);
        concluded += '\n' + vers[0];
        if (url >!< concludedUrl)
          concludedUrl += '\n' + report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "ricoh_printer/http/" + port + "/concluded", value: concluded);
    set_kb_item(name: "ricoh_printer/http/" + port + "/concludedUrl", value: concludedUrl);

    exit(0);
  }
}

exit(0);
