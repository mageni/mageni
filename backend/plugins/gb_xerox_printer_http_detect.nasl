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
  script_oid("1.3.6.1.4.1.25623.1.0.103648");
  script_version("2021-09-06T12:21:43+0000");
  script_tag(name:"last_modification", value:"2021-09-07 10:21:00 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2013-01-30 14:31:24 +0100 (Wed, 30 Jan 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Xerox Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Xerox printer devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("xerox_printers.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

urls = get_xerox_detect_urls();

foreach url (keys(urls)) {

  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  buf = http_get_cache(item: url, port: port);
  if(!buf || (buf !~ "^HTTP/1\.[01] 200" && buf !~ "^HTTP/1\.[01] 401"))
    continue;

  if(match = eregmatch(pattern: pattern, string: buf, icase: TRUE)) {

    if(isnull(match[1]))
      continue;

    model = chomp(match[1]);
    if(!isnull(match[2]))
      model += " " + chomp(match[2]);

    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/port", value: port);
    set_kb_item(name: "xerox/printer/http/" + port + "/model", value: model);

    # AltaLink
    # <tr ><td>Device Software:</td><td>100.002.008.05702</td></tr>
    vers = eregmatch(pattern: "Device Software:</td><td>([0-9.]+)<", string: buf);
    if (!isnull(vers[1])) {
      set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: vers[0]);
      set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: url);
    }
    else {
      # DocuPrint
      # Version</td><td class=std_2>201210101131</td></tr>
      vers = eregmatch(pattern: "Version</td><td class=std_2>([0-9]+)<", string: buf);
      if (!isnull(vers[1])) {
        set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
        set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: vers[0]);
        set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: url);
      }
      else {
        # ColorQube 8700/8900
        # System Software:</td><td>072.162.004.09100</td></tr>
        url = "/properties/configuration.php?tab=Status#heading2";
        res = http_get_cache(port: port, item: url);
        vers = eregmatch(pattern: "System Software:</td><td>([0-9.]+)<", string: res);
        if (!isnull(vers[1])) {
          set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
          set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: vers[0]);
          set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: url);
        }
        else {
          # ColorQube
          # <td>System Version</td>
          # <td>1.3.8.P</td>
          url = "/aboutprinter.html";
          res = http_get_cache(port: port, item: url);
          vers = eregmatch(pattern: "System Version</td>[^<]+<td>([^<]+)</td>", string: res);
          if (!isnull(vers[1])) {
            set_kb_item(name: "xerox/printer/http/" + port + "/fw_version", value: vers[1]);
            set_kb_item(name: "xerox/printer/http/" + port + "/concluded", value: vers[0]);
            set_kb_item(name: "xerox/printer/http/" + port + "/concludedUrl", value: url);
          }
        }
      }
    }

    exit(0);
  }

  else if(buf =~ "^HTTP/1\.[01] 401" && "CentreWare Internet Services" >< buf)  {

    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/http/port", value: port);

    exit(0);
  }
}

exit(0);
