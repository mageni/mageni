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
  script_oid("1.3.6.1.4.1.25623.1.0.147355");
  script_version("2021-12-20T03:43:35+0000");
  script_tag(name:"last_modification", value:"2021-12-20 03:43:35 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-20 03:23:18 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2021-44857", "CVE-2021-44858", "CVE-2021-45038");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.5, 1.36.x < 1.36.3, 1.37.x < 1.37.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44857: It is possible to use action=mcrundo followed by action=mcrrestore to replace
  the content of any arbitrary page (that the user doesn't have edit rights for)

  - CVE-2021-44858: The 'undo' feature (action=edit&undo=##&undoafter=###) allows an attacker to
  view the contents of arbitrary revisions, regardless of whether they had permissions to do so

  - CVE-2021-45038: The 'rollback' feature (action=rollback) could be passed a specially crafted
  parameter that allows an attacker to view the contents of arbitrary pages, regardless of whether
  they had permissions to do so");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.5, version 1.36.x through
  1.36.2 and 1.37.0.");

  script_tag(name:"solution", value:"Update to version 1.35.5, 1.36.3, 1.37.1 or later.");

  script_xref(name:"URL", value:"https://www.mediawiki.org/wiki/2021-12_security_release/FAQ");

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

if (version_is_less(version: version, test_version: "1.35.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.36.0", test_version2: "1.36.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.37.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
