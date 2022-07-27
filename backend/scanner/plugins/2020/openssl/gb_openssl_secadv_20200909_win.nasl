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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144563");
  script_version("2020-09-11T06:16:46+0000");
  script_tag(name:"last_modification", value:"2020-09-14 09:56:38 +0000 (Mon, 14 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 06:05:59 +0000 (Wed, 22 Apr 2020)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-1968");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Raccoon Attack (CVE-2020-1968) (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to Racoon attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Raccoon attack exploits a flaw in the TLS specification which can lead to
  an attacker being able to compute the pre-master secret in connections which have used a Diffie-Hellman (DH)
  based ciphersuite. In such a case this would result in the attacker being able to eavesdrop on all encrypted
  communications sent over that TLS connection. The attack can only be exploited if an implementation re-uses a DH
  secret across multiple TLS connections. Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites.");

  script_tag(name:"impact", value:"An attacker may eavesdrop on encrypted communications sent over a TLS connection.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 - 1.0.2v and probably 1.1.0.");

  script_tag(name:"solution", value:"Update OpenSSL to version 1.0.2w, 1.1.1 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20200909.txt");

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

if (version_in_range(version: version, test_version: "1.0.2", test_version2: "1.0.2v")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2w", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^1\.1\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
