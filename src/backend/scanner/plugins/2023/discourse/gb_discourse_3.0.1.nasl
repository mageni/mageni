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
  script_oid("1.3.6.1.4.1.25623.1.0.149209");
  script_version("2023-02-09T09:30:03+0000");
  script_tag(name:"last_modification", value:"2023-02-09 09:30:03 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-01-27 04:52:15 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-22468", "CVE-2023-23615", "CVE-2023-23616", "CVE-2023-23620",
                "CVE-2023-23621", "CVE-2023-23624", "CVE-2023-22739", "CVE-2023-25167");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-22468: Stored XSS in local oneboxes

  - CVE-2023-23615: Malicious users can create spam topics as any user

  - CVE-2023-23616: Group membership requests lack character limit

  - CVE-2023-23620: Restricted tag routes leak topic information

  - CVE-2023-23621: ReDoS in user agent parsing

  - CVE-2023-23624: Exclude_tags param could leak which topics had a specific hidden tag

  - CVE-2023-22739: DoS through topic drafts

  - CVE-2023-25167: ReDoS through installing themes via git");

  script_tag(name:"affected", value:"Discourse prior to version 3.0.1.");

  script_tag(name:"solution", value:"Update to version 3.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-8mr2-xf8r-wr8m");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7mf3-5v84-wxq8");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-6xff-p329-9pgf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hvj9-g84x-5prx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-mrfp-54hf-jrcv");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-qgj5-g5vf-fm7q");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-rqgr-g6v7-jcfc");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-4w55-w26q-r35w");

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

if (version_is_less(version: version, test_version: "3.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
