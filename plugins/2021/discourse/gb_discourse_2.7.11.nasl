# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.147244");
  script_version("2021-12-02T04:37:14+0000");
  script_tag(name:"last_modification", value:"2021-12-02 11:13:31 +0000 (Thu, 02 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-02 04:26:41 +0000 (Thu, 02 Dec 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-43792", "CVE-2021-43793", "CVE-2021-43794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.7.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-43792: Users without tag group permissions can view and receive notifications for
  previously watched tags

  - CVE-2021-43793: Bypass of Poll voting limits

  - CVE-2021-43794: Anonymous user cache poisoning via development-mode header");

  script_tag(name:"affected", value:"Discourse prior to version 2.7.11.");

  script_tag(name:"solution", value:"Update to version 2.7.11 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-pq2x-vq37-8522");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jq7h-44vc-h6qx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-249g-pc77-65hp");

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

if (version_is_less(version: version, test_version: "2.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
