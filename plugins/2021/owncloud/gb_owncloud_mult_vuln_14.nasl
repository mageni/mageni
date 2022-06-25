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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146736");
  script_version("2021-09-21T12:01:22+0000");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-21 09:24:40 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-12 20:17:00 +0000 (Wed, 12 Feb 2020)");

  script_cve_id("CVE-2014-2050", "CVE-2014-2052");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 5.0.15, 6.0.x < 6.0.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-2050: Cross-site request forgery (CSRF) allows remote attackers to hijack the
  authentication of users for requests that reset passwords via a crafted HTTP Host header.

  - CVE-2014-2052: Zend Framework, as used in ownCloud Server, allows remote attackers to read
  arbitrary files, cause a denial of service, or possibly have other impact via an XML External
  Entity (XXE) attack.");

  script_tag(name:"affected", value:"ownCloud prior to version 5.0.15 and version 6.0.x through 6.0.1.");

  script_tag(name:"solution", value:"Update to version 5.0.15, 6.0.2 or later.");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisories/host-header-poisoning/");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisories/xxe-multiple-third-party-components/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);