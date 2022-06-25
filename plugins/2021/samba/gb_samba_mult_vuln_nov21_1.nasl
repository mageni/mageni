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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147123");
  script_version("2021-11-11T02:09:03+0000");
  script_tag(name:"last_modification", value:"2021-11-11 02:09:03 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-11 01:42:45 +0000 (Thu, 11 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-25722", "CVE-2021-3738", "CVE-2020-25718", "CVE-2020-25719",
                "CVE-2020-25721");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 4.0.0 < 4.13.14, 4.14.0 < 4.14.10, 4.15.0 < 4.15.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-25718: Samba AD DC does not correctly sandbox Kerberos tickets issued by an RODC

  - CVE-2020-25719: Samba AD DC does not always rely on the SID and PAC in Kerberos tickets

  - CVE-2020-25721: Kerberos acceptors need easy access to stable AD identifiers (eg objectSid)

  - CVE-2020-25722: Samba AD DC does not do suffienct access and conformance checking of data
  stored

  - CVE-2021-3738: Use after free in Samba AD DC RPC server");

  script_tag(name:"affected", value:"Samba version 4.x through 4.13.13, 4.14.x through 4.14.9 and
  4.15.x through 4.15.1.");

  script_tag(name:"solution", value:"Update to version 4.13.14, 4.14.10, 4.15.2 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25718.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25719.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25721.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2020-25722.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-3738.html");

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

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.13.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.13.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.14.0", test_version2: "4.14.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.14.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.15.0", test_version2: "4.15.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
