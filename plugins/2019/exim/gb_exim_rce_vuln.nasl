# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140090");
  script_version("2019-06-07T01:42:55+0000");
  script_tag(name:"last_modification", value:"2019-06-07 01:42:55 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-07 01:35:15 +0000 (Fri, 07 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-10149");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.87 - 4.91 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_exim_detect.nasl");
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to an unauthenticated remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper validation of recipient address in deliver_message() function in
  /src/deliver.c may lead to remote command execution.");

  script_tag(name:"affected", value:"Exim version 4.87 to 4.91.");

  script_tag(name:"solution", value:"Update to version 4.92 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2019-10149.txt");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/06/05/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.87", test_version2: "4.91")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.92");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
