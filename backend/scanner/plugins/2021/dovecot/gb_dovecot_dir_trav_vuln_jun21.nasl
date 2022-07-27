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

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117513");
  script_version("2021-06-28T11:58:37+0000");
  script_tag(name:"last_modification", value:"2021-06-29 10:13:44 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-28 11:44:06 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2021-29157");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.3.11 - 2.3.14 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a path traversal vulnerability.");

  script_tag(name:"insight", value:"Dovecot does not correctly escape kid and azp fields in JWT
  tokens. This may be used to supply attacker controlled keys to validate tokens in some
  configurations. This requires attacker to be able to write files to local disk.");

  script_tag(name:"impact", value:"Local attacker can login as any user and access their emails.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot version 2.3.11 through 2.3.14.");

  script_tag(name:"solution", value:"Update to version 2.3.14.1 or later.

  Workaround:

  Disable local JWT validation in oauth2, or use a different dict driver than fs:posix.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000461.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000459.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.3.11", test_version2: "2.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);