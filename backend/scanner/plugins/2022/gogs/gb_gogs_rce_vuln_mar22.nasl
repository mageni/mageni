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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124042");
  script_version("2022-03-23T12:27:29+0000");
  script_tag(name:"last_modification", value:"2022-03-23 12:27:29 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 08:21:55 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-0415");

  script_name("Gogs < 0.12.6 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The malicious user is able to upload a crafted config file into
  repository's .git directory with the goal to gain SSH access to the server.");

  script_tag(name:"affected", value:"Gogs versions prior to 0.12.6.

  All installations with repository upload enabled (default) are affected.");

  script_tag(name:"solution", value:"Update to version 0.12.6 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/releases/tag/v0.12.6");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/6833");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-5gjh-5j4f-cpwv");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/commit/0fef3c9082269e9a4e817274942a5d7c50617284");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/b4928cfe-4110-462f-a180-6d5673797902");

  exit(0);
}

CPE = "cpe:/a:gogs:gogs";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.12.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
