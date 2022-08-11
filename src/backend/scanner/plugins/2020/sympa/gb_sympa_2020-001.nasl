# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:sympa:sympa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143551");
  script_version("2020-02-25T05:07:11+0000");
  script_tag(name:"last_modification", value:"2020-02-25 11:00:29 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-25 04:59:28 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-9369");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sympa 6.2.38 <= 6.2.52 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("sympa_detect.nasl");
  script_mandatory_keys("sympa/detected");

  script_tag(name:"summary", value:"Sympa is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By submitting requests with malformed parameters, this flaw allows to create
  junk files in Sympa's directory for temporary files. And particularly by tampering token to prevent CSRF, it
  allows to originate exessive notification messages to listmasters.");

  script_tag(name:"affected", value:"Sympa version 6.2.38 to 6.2.52.");

  script_tag(name:"solution", value:"Update to version 6.2.54 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://sympa-community.github.io/security/2020-001.html");
  script_xref(name:"URL", value:"https://github.com/sympa-community/sympa/issues/886");

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

if (version_in_range(version: version, test_version: "6.2.38", test_version2: "6.2.52")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.54", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
