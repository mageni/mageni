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

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144337");
  script_version("2020-07-31T03:15:17+0000");
  script_tag(name:"last_modification", value:"2020-07-31 10:00:11 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-31 03:07:45 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-9689", "CVE-2020-9690", "CVE-2020-9691", "CVE-2020-9692");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Patch version not retrievable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento <= 2.3.5-p1 Multiple Vulnerabilities (APSB20-47)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Path traversal (CVE-2020-9689)

  - Observable timing discrepancy (CVE-2020-9690)

  - DOM-based cross-site scripting (CVE-2020-9691)

  - Security mitigation bypass (CVE-2020-9692)");

  script_tag(name:"affected", value:"Magento version 2.3.5-p1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.5-p2, 2.4.0 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/magento/apsb20-47.html");

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

if (version_is_less_equal(version: version, test_version: "2.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.5-p2/2.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
