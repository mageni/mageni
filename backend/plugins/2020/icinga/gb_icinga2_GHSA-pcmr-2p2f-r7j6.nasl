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

CPE = "cpe:/a:icinga:icinga2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145077");
  script_version("2020-12-21T09:02:28+0000");
  script_tag(name:"last_modification", value:"2020-12-21 09:02:28 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-21 07:16:02 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-29663");

  script_name("Icinga 2.8.0 < 2.11.8, 2.12.2 < 2.12.3 CRL Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_icinga2_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga 2 is prone to a vulnerability where revoked certificates are
  automatically renewed ignoring the CRL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Revoked certificates due for renewal will automatically be renewed ignoring
  the CRL.

  When a CRL is specified in the ApiListener configuration, Icinga 2 only used it when connections were established
  so far, but not when a certificate is requested. This allows a node to automatically renew a revoked certificate
  if it meets the other conditions for auto renewal (issued before 2017 or expires in less than 30 days).

  Because Icinga 2 currently uses a validity duration of 15 years, this only affects setups with external
  certificate signing and revoked certificates that expire in less then 30 days.");

  script_tag(name:"affected", value:"Icinga versions 2.8.0 - 2.11.7 and 2.12.2.");

  script_tag(name:"solution", value:"Update to version 2.11.8, 2.12.3 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/security/advisories/GHSA-pcmr-2p2f-r7j6");

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

if (version_in_range(version: version, test_version: "2.8.0", test_version2: "2.11.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.11.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "2.12.2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
