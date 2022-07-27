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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147536");
  script_version("2022-01-31T03:47:25+0000");
  script_tag(name:"last_modification", value:"2022-01-31 10:37:41 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-31 03:36:36 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-4160");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: BN_mod_exp may produce incorrect results on MIPS (CVE-2021-4160) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a carry propagation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a carry propagation bug in the MIPS32 and MIPS64
  squaring procedure. Many EC algorithms are affected, including some of the TLS 1.3 default
  curves. Impact was not analyzed in detail, because the pre-requisites for attack are considered
  unlikely and include reusing private keys.  Analysis suggests that attacks against RSA and DSA as
  a result of this defect would be very difficult to perform and are not believed likely. Attacks
  against DH are considered just feasible (although very difficult) because most of the work
  necessary to deduce information about a private key may be performed offline. The amount of
  resources required for such an attack would be significant. However, for an attack on TLS to be
  meaningful, the server would have to share the DH private key among multiple clients, which is no
  longer an option since CVE-2016-0701.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.2, 1.1.1 and 3.0.0.");

  script_tag(name:"solution", value:"Update to version 1.1.1m, 3.0.1 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220128.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.2", test_version_up: "1.1.1m")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1m", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.0.0", test_version_up: "3.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
