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
  script_oid("1.3.6.1.4.1.25623.1.0.142906");
  script_version("2019-09-19T02:14:12+0000");
  script_tag(name:"last_modification", value:"2019-09-19 02:14:12 +0000 (Thu, 19 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-18 03:01:18 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("toshiba_printers.inc");

port = get_http_port(default: 8080);

urls = get_toshiba_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "toshiba_printer/detected", value: TRUE);
    set_kb_item(name: "toshiba_printer/http/detected", value: TRUE);
    set_kb_item(name: "toshiba_printer/http/port", value: port);

    url2 = "/TopAccess/Device/Device.htm";
    res2 = http_get_cache(port: port, item: url2);

    mod = eregmatch(pattern: ">Copier Model.*>TOSHIBA ([^&]+)", string: res2);
    if (!isnull(mod[1])) {
      set_kb_item(name: "toshiba_printer/http/" + port + "/model", value: mod[1]);
      set_kb_item(name: "toshiba_printer/http/" + port + "/concluded", value: mod[0]);
      set_kb_item(name: "toshiba_printer/http/" + port + "/concludedUrl",
                  value: report_vuln_url(port: port, url: url2, url_only: TRUE));
    } else {
      cookie = http_get_cookie_from_header(buf: res, pattern: "(Session=[^;]+;)");
      if (!isnull(cookie)) {
        url2 = "/contentwebserver";
        data = "<DeviceInformationModel><GetValue><MFP><ModelName></ModelName></MFP></GetValue></DeviceInformationModel>";
        csrfpid = ereg_replace(pattern: "Session=(.*);", string: cookie, replace: "\1");
        headers = make_array("Cookie", cookie += "Locale=en-US,en#q=0.5;",
                             "csrfpId", csrfpid);

        # <DeviceInformationModel><GetValue><MFP><ModelName>TOSHIBA e-STUDIO3005AC</ModelName></MFP></GetValue></DeviceInformationModel>
        req = http_post_req(port: port, url: url2, data: data, add_headers: headers);
        res2 = http_keepalive_send_recv(port: port, data: req);

        mod = eregmatch(pattern: "<ModelName>TOSHIBA ([^<]+)<", string: res2);
        if (!isnull(mod[1])) {
          set_kb_item(name: "toshiba_printer/http/" + port + "/model", value: mod[1]);
          set_kb_item(name: "toshiba_printer/http/" + port + "/concluded", value: mod[0]);
          set_kb_item(name: "toshiba_printer/http/" + port + "/concludedUrl",
                      value: report_vuln_url(port: port, url: url2, url_only: TRUE));
        }
      } else {
        if (!isnull(match[1])) {
          set_kb_item(name: "toshiba_printer/http/" + port + "/model", value: match[1]);

          url2 = '/cgi-bin/dynamic/printer/config/reports/deviceinfo.html';
          headers = make_array("Cookie", "lexlang=0;"); # language should be English as default language might differ. nb: Older firmware had shared the same code-base with Lexmark printers

          req = http_get_req(port: port, url: url2, add_headers: headers);
          res2 = http_keepalive_send_recv(port: port, data: req);

          # >Base</p></td><td><p> =  LW60.GM7.P632-0 </p></td>
          vers = eregmatch(pattern: '>Base</p></td><td><p> =  ([^ ]+)', string: res2);
          if (!isnull(vers[1])) {
            set_kb_item(name: "toshiba_printer/http/" + port + "/fw_version", value: vers[1]);
            set_kb_item(name: "toshiba_printer/http/" + port + "/concluded", value: vers[0]);
            set_kb_item(name: "toshiba_printer/http/" + port + "/concludedUrl",
                        value: report_vuln_url(port: port, url: url2, url_only: TRUE));
          }
        }
      }
    }

    exit(0);
  }
}

exit(0);
