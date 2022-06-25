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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145405");
  script_version("2021-02-17T06:24:44+0000");
  script_tag(name:"last_modification", value:"2021-02-17 11:09:13 +0000 (Wed, 17 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-17 05:49:06 +0000 (Wed, 17 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-23839");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: Incorrect SSLv2 rollback protection (CVE-2021-23839) (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to an incorrect SSLv2 rollback protection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with
  a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made
  for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions
  greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2
  is supposed to reject connection attempts from a client where this special form of padding is present,
  because this indicates that a version rollback has occurred (i.e. both client and server support greater
  than SSLv2, and yet this is the version that is being requested).

  The implementation of this padding check inverted the logic so that the connection attempt is accepted if
  the padding is present, and rejected if it is absent. This means that such as server will accept a connection
  if a version rollback attack has occurred. Further the server will erroneously reject a connection if a
  normal SSLv2 connection attempt is made.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2s - 1.0.2x.");

  script_tag(name:"solution", value:"Update OpenSSL to version 1.0.2y, 1.1.1j or later. See the references for
  more details.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210216.txt");

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

if (version_in_range(version: version, test_version: "1.0.2s", test_version2: "1.0.2x")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.2y / 1.1.1j", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
