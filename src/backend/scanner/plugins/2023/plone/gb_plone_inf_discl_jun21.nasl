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

CPE = "cpe:/a:plone:plone";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124286");
  script_version("2023-02-24T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-24 10:08:40 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-21 04:07:06 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2021-33926");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Hotfix not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plone CMS 4.3.0 <= 5.2.4 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plone_http_detect.nasl");
  script_mandatory_keys("plone/detected");

  script_tag(name:"summary", value:"Plone CMS is prone to an information disclosure vulnerability
  via a server-side request forgery (SSRF) flaw.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A blind SSRF flaw exists allowing the feedparser accessing an
  internal URL.");

  script_tag(name:"impact", value:"By adding an RSS feed portlet in their dashboard, a normal member
  could try loading the RSS feed of an internal service which is otherwise unreachable for this
  member. This could allow an attacker to access sensitive information.");

  script_tag(name:"affected", value:"Plone CMS version 4.3.0 through 5.2.4.");

  script_tag(name:"solution", value:"Install hotfix package 1.6 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-47p5-p3jw-w78w");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20210518");

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

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "5.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply hotfix package 1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
