# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:matrixssl:matrixssl";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126302");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-19 10:31:52 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-46505");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("MatrixSSL <= 4.5.1 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_matrixssl_http_detect.nasl");
  script_mandatory_keys("matrixssl/detected");

  script_tag(name:"summary", value:"MatrixSSL is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Securely check fails in the SessionID field, resulting in the
  misuse of an all-zero MasterSecret that can decrypt secret data");

  script_tag(name:"affected", value:"MatrixSSL version 4.5.1 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 19th January, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/SmallTown123/details-for-CVE-2022-46505");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/blob/4-6-0-open/doc/CHANGES_v4.x.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
