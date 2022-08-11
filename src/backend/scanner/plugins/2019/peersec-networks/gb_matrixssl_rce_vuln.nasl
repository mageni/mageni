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
  script_oid("1.3.6.1.4.1.25623.1.0.142232");
  script_version("2019-04-09T08:37:50+0000");
  script_tag(name:"last_modification", value:"2019-04-09 08:37:50 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-09 08:17:00 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-10914");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL 4.0.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"MatrixSSL is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A maliciously crafted certificate can be used to trigger a stack buffer
  overflow, allowing potential remote code execution attacks. The vulnerability only affects version 4.0.1 and the
  standard Matrix Crypto provider. Other providers, such as the FIPS crypto provider, are not affected by the
  bug.");

  script_tag(name:"affected", value:"MatrixSSL version 4.0.1.");

  script_tag(name:"solution", value:"Update to version 4.0.2 or above.");

  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/releases/tag/4-0-2-open");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/issues/26");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "4.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
