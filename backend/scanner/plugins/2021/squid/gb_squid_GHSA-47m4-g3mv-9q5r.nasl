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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146940");
  script_version("2021-10-19T08:55:52+0000");
  script_tag(name:"last_modification", value:"2021-10-19 10:35:24 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-19 08:48:37 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2021-41611");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Certificate Validation Vulnerability (SQUID-2021:6, GHSA-47m4-g3mv-9q5r)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to a certificate validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When validating an origin server or peer certificate, Squid may
  incorrectly classify certain certificates as trusted.

  This problem is guaranteed to occur when multiple CA have signed the TLS server certificate. It
  may also occur in cases of broken server certificate chains.");

  script_tag(name:"impact", value:"This problem allows a remote server to obtain security trust
  when the trust is not valid. This indication of trust may be passed along to clients allowing
  access to unsafe or hijacked services.");

  script_tag(name:"affected", value:"Squid version 5.0.6 through 5.1.");

  script_tag(name:"solution", value:"Update to version 5.2 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-47m4-g3mv-9q5r");

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

if (version_in_range(version: version, test_version: "5.0.6", test_version2: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
