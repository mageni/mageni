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

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.143814");
  script_version("2020-05-05T06:16:11+0000");
  script_tag(name:"last_modification", value:"2020-05-05 06:16:11 +0000 (Tue, 05 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-05 06:13:19 +0000 (Tue, 05 May 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-9387");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara 18.10 < 18.10.6, 19.04 < 19.04.5, 19.10 < 19.10.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"Mahara is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"Account details are shared in the Elasticsearch results for accounts that are
  not accessible when the config setting 'Isolated institutions' is turned on.");

  script_tag(name:"affected", value:"Mahara versions 18.10, 19.04 and 19.10.");

  script_tag(name:"solution", value:"Update to version 18.10.6, 19.04.5, 19.10.3 or later.");

  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8612");

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

if (version_in_range(version: version, test_version: "18.10.0", test_version2: "18.10.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "19.04.0", test_version2: "19.04.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.04.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "19.10.0", test_version2: "19.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.10.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
