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

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148852");
  script_version("2022-11-03T14:19:40+0000");
  script_tag(name:"last_modification", value:"2022-11-03 14:19:40 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-03 10:56:07 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2022-39241", "CVE-2022-39356", "CVE-2022-39378");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.8.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-39241: Insufficient server-side request forgery protections

  - CVE-2022-39356: User account takeover via invite links

  - CVE-2022-39378: Displaying user badges can leak topic titles to users that have no access to
  the topic");

  script_tag(name:"affected", value:"Discourse prior to version 2.8.10.");

  script_tag(name:"solution", value:"Update to version 2.8.10 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-rcc5-28r3-23rr");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-x8w7-rwmr-w278");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-2gvq-27h6-4h5f");

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

if (version_is_less(version: version, test_version: "2.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
