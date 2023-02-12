# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149071");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-06 04:55:43 +0000 (Fri, 06 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-46168", "CVE-2022-46177", "CVE-2022-23548", "CVE-2022-23549",
                "CVE-2023-22453", "CVE-2023-22454", "CVE-2023-22455");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.0.0.beta16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-46168: Group SMTP user emails are exposed in CC email header

  - CVE-2022-46177: Password reset link can lead to in account takeover if user changes to a new
  email

  - CVE-2022-23548: Regex susceptible to ReDOS

  - CVE-2022-23549: Bypass of post max_length using HTML comments

  - CVE-2023-22453: Exposure of user post counts per topic to unauthorized users

  - CVE-2023-22454: XSS through pending post titles descriptions

  - CVE-2023-22455: XSS through tag descriptions");

  script_tag(name:"affected", value:"Discourse prior to version 3.0.0.beta16.");

  script_tag(name:"solution", value:"Update to version 3.0.0.beta16 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-8p7g-3wm6-p3rm");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7rw2-f4x7-7pxf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-p47g-v5wr-p4xp");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-xx97-6494-p2rv");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-ggq4-4qxc-c462");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5rq6-466r-6mr9");

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

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta15") ||
    version_in_range(version: version, test_version: "3.0.0.beta1", test_version2: "3.0.0.beta15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0.beta16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
