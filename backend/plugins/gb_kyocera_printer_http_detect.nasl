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
  script_oid("1.3.6.1.4.1.25623.1.0.103707");
  script_version("2022-01-31T13:17:52+0000");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-05-08 11:31:24 +0100 (Wed, 08 May 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kyocera Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kyocera printer devices.");

  exit(0);
}

include("kyocera_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 80);

urls = kyocera_get_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(item: url, port: port);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "kyocera/printer/detected", value: TRUE);
    set_kb_item(name: "kyocera/printer/http/detected", value: TRUE);
    set_kb_item(name: "kyocera/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[1])) {
      model = match[1];
      set_kb_item(name: "kyocera/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "kyocera/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    url = "/dvcinfo/dvcconfig/DvcConfig_Config.htm";
    res = http_get_cache(port: port, item: url);

    # ComnAddLabelProperty('2',mes[193] + " :","2PJ_3F00.003.014","w272px");
    vers = eregmatch(pattern: "ComnAddLabelProperty\('2',mes\[193\][^,]+," + '"([^"]+)"', string: res);
    if (!isnull(vers[1])) {
      fw_version = vers[1];
      set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
      set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else {
      url = "/start/start.htm";
      res = http_get_cache(port: port, item: url);

      # sData[4] = "2MH_2F00.004.002";  // System Firmware
      vers = eregmatch(pattern: 'sData\\[[0-9]\\]\\s*=\\s*"([^"]+)";\\s*//\\s*System Firmware',
                       string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      } else {
        url = "/js/jssrc/model/dvcinfo/dvcconfig/DvcConfig_Config.model.htm?arg1=0";
        res = http_get_cache(port: port, item: url);

        # _pp.system = '2V8_S000.002.232';
        vers = eregmatch(pattern: "_pp.system\s*=\s*'([^']+)'", string: res);
        if (!isnull(vers[1])) {
          fw_version = vers[1];
          set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
          set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                      value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
        }
      }
    }

    set_kb_item(name: "kyocera/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "kyocera/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

banner = http_get_remote_headers(port: port);

# e.g.:
# Server: KM-MFP-http/V0.0.1
# nb: Keep in sync with dont_print_on_printers.nasl and sw_http_os_detection.nasl
if (concl = egrep(pattern: "^Server\s*:\s*KM-MFP-http", string: banner, icase: TRUE)) {
  concl = chomp(concl);

  set_kb_item(name: "kyocera/printer/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/http/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/http/port", value: port);

  model = "unknown";
  fw_version = "unknown";

  set_kb_item(name: "kyocera/printer/http/" + port + "/model", value: model);
  set_kb_item(name: "kyocera/printer/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "kyocera/printer/http/" + port + "/generalConcluded", value: concl);
}

exit(0);
