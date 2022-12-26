# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:inverse-inc:sogo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127286");
  script_version("2022-12-21T11:40:46+0000");
  script_tag(name:"last_modification", value:"2022-12-21 11:40:46 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-21 08:40:39 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2022-4556", "CVE-2022-4558");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SOGo < 5.8.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_inverseinc_sogo_detect.nasl");
  script_mandatory_keys("inverse/sogo/detected");

  script_tag(name:"summary", value:"SOGo is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4556: Cross-site scripting (XSS) affects _migrateMailIdentities function in the
  'SoObjects/SOGo/SOGoUserDefaults.m' file of the Identity Handler component.

  - CVE-2022-4558: Cross-site scripting (XSS) affects an unknown part of the file
  'SoObjects/SOGo/NSString+Utilities.m' of the Folder/Mail Handler component.");

  script_tag(name:"affected", value:"SOGo prior to version 5.8.0");

  script_tag(name:"solution", value:"Update to version 5.8.0 or later.");

  script_xref(name:"URL", value:"https://vuldb.com/?id.215960");
  script_xref(name:"URL", value:"https://github.com/Alinto/sogo/commit/efac49ae91a4a325df9931e78e543f707a0f8e5e");
  script_xref(name:"URL", value:"https://vuldb.com/?id.215961");
  script_xref(name:"URL", value:"https://github.com/Alinto/sogo/commit/1e0f5f00890f751e84d67be4f139dd7f00faa5f3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
