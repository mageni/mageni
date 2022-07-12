# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143602");
  script_version("2020-03-17T08:47:40+0000");
  script_tag(name:"last_modification", value:"2020-03-18 13:55:00 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-17 08:24:39 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-10240", "CVE-2020-10242");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 3.0.0 - 3.9.15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla! is prone to multiple vulnerabilities:

  - Missing length checks in the user table can lead to the creation of users with duplicate usernames and/or
    email addresses (CVE-2020-10240)

  - Inadequate handling of CSS selectors in the Protostar and Beez3 JavaScript allow XSS attacks (CVE-2020-10242)");

  script_tag(name:"affected", value:"Joomla! versions 3.0.0 - 3.9.15.");

  script_tag(name:"solution", value:"Update to version 3.9.16 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/805-20200304-core-identifier-collisions-in-com-users");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/803-20200302-core-xss-in-protostar-and-beez3");


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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.9.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.16", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
