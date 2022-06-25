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

CPE = "cpe:/a:qnap:photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146820");
  script_version("2021-10-04T07:23:25+0000");
  script_tag(name:"last_modification", value:"2021-10-04 10:20:00 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-04 07:20:33 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-34354", "CVE-2021-34356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP NAS Photo Station Multiple XSS Vulnerabilities (QSA-21-41)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("QNAP/QTS/PhotoStation/detected");

  script_tag(name:"summary", value:"QNAP NAS Photo Station is prone to two stored cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"impact", value:"If exploited, these vulnerabilities allow remote attackers to
  inject malicious code.");

  script_tag(name:"affected", value:"QNAP Photo Station prior to version 6.0.18.");

  script_tag(name:"solution", value:"Update to version 6.0.18 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-21-41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.18");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
