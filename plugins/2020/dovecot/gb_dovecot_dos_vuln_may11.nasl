# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:dovecot:dovecot";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114173");
  script_version("2020-01-07T12:10:22+0000");
  script_tag(name:"last_modification", value:"2020-01-07 12:10:22 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-06 10:15:27 +0100 (Mon, 06 Jan 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-1929");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 1.2.x < 1.2.17 / 2.0.x < 2.0.13 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a Denial of Service vulnerability.");

  script_tag(name:"insight", value:"Lib-mail/message-header-parser.c does not properly handle
  null-termination in header names, which allows remote attackers to cause a Denial of Service
  (daemon crash or mailbox corruption) via a crafted e-mail message.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot versions 1.2.x before 1.2.17 and 2.0.x before 2.0.13.");

  script_tag(name:"solution", value:"Update to version 1.2.17/2.0.13 or later.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot/2011-May/059085.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot/2011-May/059086.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_greater_equal(version: version, test_version: "1.2.0") && version_is_less(version: version, test_version: "1.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
} else if(version_is_greater_equal(version: version, test_version: "2.0.0") && version_is_less(version: version, test_version: "2.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
