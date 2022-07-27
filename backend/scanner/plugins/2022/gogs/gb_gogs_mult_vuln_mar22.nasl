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
  script_oid("1.3.6.1.4.1.25623.1.0.124038");
  script_version("2022-03-16T18:40:05+0000");
  script_tag(name:"last_modification", value:"2022-03-17 11:18:10 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-16 08:21:55 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-0870", "CVE-2022-0871");

  script_name("Gogs < 0.12.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0870: Server-Side Request Forgery (SSRF)

  - CVE-2022-0871: Improper authorization");

  script_tag(name:"affected", value:"Gogs versions prior to 0.12.5.");

  script_tag(name:"solution", value:"Update to version 0.12.5 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/commit/91f2cde5e95f146bfe4765e837e7282df6c7cabb");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/327797d7-ae41-498f-9bff-cc0bf98cf531");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/commit/64102be2c90e1b47dbdd379873ba76c80d4b0e78");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/ea82cfc9-b55c-41fe-ae58-0d0e0bd7ab62");

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

if (version_is_less(version: version, test_version: "0.12.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
