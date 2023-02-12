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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104511");
  script_version("2023-02-06T10:09:59+0000");
  script_tag(name:"last_modification", value:"2023-02-06 10:09:59 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 13:51:53 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenBSD OpenSSH 8.7 - 9.1 Unspecified Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_tag(name:"summary", value:"OpenBSD OpenSSH is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The PermitRemoteOpen option would ignore its first argument
  unless it was one of the special keywords 'any' or 'none', causing the permission list to fail
  open if only one permission was specified.");

  script_tag(name:"affected", value:"OpenBSD OpenSSH versions 8.7 through 9.1.");

  script_tag(name:"solution", value:"Update to version 9.2 or later.");

  script_xref(name:"URL", value:"https://www.openssh.com/releasenotes.html#9.2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/02/02/3");

  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.7", test_version2: "9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
