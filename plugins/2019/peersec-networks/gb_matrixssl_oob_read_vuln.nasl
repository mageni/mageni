# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:peersec_networks:matrixssl";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112605");
  script_version("2019-07-11T13:03:44+0000");
  script_tag(name:"last_modification", value:"2019-07-11 13:03:44 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-11 14:57:00 +0200 (Thu, 11 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-13470");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL 4.2.1 Out-Of-Bounds Read Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"MatrixSSL is prone to an out-of-bounds read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in ASN.1 handling.");

  script_tag(name:"affected", value:"MatrixSSL before version 4.2.1.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/blob/4-2-1-open/doc/CHANGES_v4.x.md#changes-between-420-and-421-june-2019");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version: version, test_version: "4.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
