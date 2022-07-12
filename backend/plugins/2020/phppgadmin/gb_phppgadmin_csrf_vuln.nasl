# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:phppgadmin:phppgadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143530");
  script_version("2020-02-20T07:33:44+0000");
  script_tag(name:"last_modification", value:"2020-02-20 07:33:44 +0000 (Thu, 20 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 07:05:15 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-10784");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("phpPgAdmin <= 7.12.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phppgadmin_detect.nasl");
  script_mandatory_keys("phppgadmin/detected");

  script_tag(name:"summary", value:"phpPgAdmin is prone to a cross-site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpPgAdmin allows sensitive actions to be performed without validating that
  the request originated from the application. One such area, 'database.php' does not verify the source of an HTTP
  request. This can be leveraged by a remote attacker to trick a logged-in administrator to visit a malicious page
  with a CSRF exploit and execute arbitrary system commands on the server.");

  script_tag(name:"affected", value:"phpPgAdmin version 7.12.1 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 20th February, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-PHP-PHPPGADMINPHPPGADMIN-543885");

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

if (version_is_less_equal(version: version, test_version: "7.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
