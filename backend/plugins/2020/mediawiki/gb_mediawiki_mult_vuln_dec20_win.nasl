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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145084");
  script_version("2020-12-22T08:50:42+0000");
  script_tag(name:"last_modification", value:"2020-12-22 08:50:42 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-22 08:49:57 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-35474", "CVE-2020-35475", "CVE-2020-35477", "CVE-2020-35478", "CVE-2020-35479",
                "CVE-2020-35480");

  script_name("MediaWiki < 1.31.11, 1.32 < 1.35.1 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Message recentchanges-legend-watchlistexpiry can contain raw html (CVE-2020-35474)

  - Messages userrights-expiry-current and userrights-expiry-none can contain raw html (CVE-2020-35475)

  - BlockLogFormatter can output raw html (CVE-2020-35478, CVE-2020-35479)

  - Unable to change visibility of log entries when MediaWiki:Mainpage uses Special:MyLanguage (CVE-2020-35477)

  - Divergent behavior for contributions and user pages of hidden users and missing users (CVE-2020-35480)");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.31.11 or 1.35.1.");

  script_tag(name:"solution", value:"Update to version 1.31.11, 1.35.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-December/000268.html");

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

if (version_is_less(version: version, test_version: "1.31.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.32", test_version2: "1.35.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
