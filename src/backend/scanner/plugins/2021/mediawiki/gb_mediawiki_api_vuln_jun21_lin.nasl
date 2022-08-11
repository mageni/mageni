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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146243");
  script_version("2021-07-08T06:50:23+0000");
  script_tag(name:"last_modification", value:"2021-07-08 10:00:03 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-08 06:37:37 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-35197");

  script_name("MediaWiki < 1.31.15, 1.32.x < 1.35.3, 1.36.x < 1.36.1 API Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to a vulnerability in the Action APi.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In MediaWiki bots have certain unintended API access. When a
  bot account has a 'sitewide block' applied, it is able to still 'purge' pages through the
  MediaWiki Action API (which a 'sitewide block' should have prevented).");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.31.15, version 1.32.x through
  1.35.2 and version 1.36.0.");

  script_tag(name:"solution", value:"Update to version 1.31.15, 1.35.3, 1.36.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/YR3X4L2CPSEJVSY543AWEO65TD6APXHP/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T280226");

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

if (version_is_less(version: version, test_version: "1.31.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.32.0", test_version2: "1.35.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "1.36.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
