# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mit:kerberos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149052");
  script_version("2023-01-03T10:12:12+0000");
  script_tag(name:"last_modification", value:"2023-01-03 10:12:12 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-03 02:28:45 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-42898");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MIT Kerberos5 < 1.19.4, 1.20.x < 1.20.1 Integer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kerberos5_ssh_login_detect.nasl");
  script_mandatory_keys("mit/kerberos5/detected");

  script_tag(name:"summary", value:"MIT Kerberos5 is prone to an integer overflow vulnerability in
  PAC parsing.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"PAC parsing has integer overflows that may lead to remote code
  execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which
  have a resultant heap-based buffer overflow), and cause a denial of service on other platforms.");

  script_tag(name:"affected", value:"MIT Kerberos5 version 1.19.3 and prior and version 1.20.0.");

  script_tag(name:"solution", value:"Update to version 1.19.4, 1.20.1 or later.");

  script_xref(name:"URL", value:"https://web.mit.edu/kerberos/krb5-1.19/");
  script_xref(name:"URL", value:"https://web.mit.edu/kerberos/krb5-1.20/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.19.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
