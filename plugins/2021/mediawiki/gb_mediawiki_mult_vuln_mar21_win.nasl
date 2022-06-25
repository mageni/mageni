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
  script_oid("1.3.6.1.4.1.25623.1.0.112880");
  script_version("2021-04-07T13:11:56+0000");
  script_tag(name:"last_modification", value:"2021-04-07 13:11:56 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-07 13:10:11 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-30154", "CVE-2021-30157", "CVE-2021-30158");

  script_name("MediaWiki < 1.31.12, 1.32 < 1.35.2 Multiple Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-30154: On Special:NewFiles, all the mediastatistics-header-* messages are output in HTML unescaped, leading to XSS.

  - CVE-2021-30157: On ChangesList special pages such as Special:RecentChanges and Special:Watchlist, some of the rcfilters-filter-* label
  messages are output in HTML unescaped, leading to XSS.

  - CVE-2021-30158: Blocked users are unable to use Special:ResetTokens. This has security relevance because a blocked user
  might have accidentally shared a token, or might know that a token has been compromised, and yet is not able to block any potential
  future use of the token by an unauthorized party.");

  script_tag(name:"affected", value:"MediaWiki through 1.31.11 and from 1.32 through 1.35.1.");

  script_tag(name:"solution", value:"Update to 1.31.12 or 1.35.2 respectively.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T278014");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T278058");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T277009");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "1.31.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.31.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "1.32", test_version2: "1.35.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
