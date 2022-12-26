# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104447");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-30 11:53:10 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("vBulletin < 5.5.3 PHP Object Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"vBulletin versions prior to 5.5.3.");

  script_tag(name:"solution", value:"According to the security researcher the vendor has fixed this
  flaw in version 5.5.3 or later.");

  script_xref(name:"URL", value:"https://karmainsecurity.com/exploiting-an-nday-vbulletin-php-object-injection");
  script_xref(name:"URL", value:"https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4418489-vbulletin-connect-5-5-3-is-now-available-for-download");

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

if (version_is_less(version: version, test_version: "5.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
