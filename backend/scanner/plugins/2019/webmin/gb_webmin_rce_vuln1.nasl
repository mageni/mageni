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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142804");
  script_version("2019-08-27T12:09:30+0000");
  script_tag(name:"last_modification", value:"2019-08-27 12:09:30 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 07:44:51 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15642");

  script_name("Webmin < 1.930 Remote Code Execution (RCE) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("usermin_or_webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to an authenticated remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"rpc.cgi in Webmin through 1.920 allows authenticated Remote Code Execution via
  a crafted object name because unserialise_variable makes an eval call.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to gain
  control over the target system.");

  script_tag(name:"affected", value:"Webmin version 1.920 and prior.");

  script_tag(name:"solution", value:"Update to version 1.930 or later.");

  script_xref(name:"URL", value:"https://www.calypt.com/blog/index.php/authenticated-rce-on-webmin/");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/df8a43fb4bdc9c858874f72773bcba597ae9432c");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.930")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.930", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
