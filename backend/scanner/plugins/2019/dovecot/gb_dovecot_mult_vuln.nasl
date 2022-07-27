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

CPE = "cpe:/a:dovecot:dovecot";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142826");
  script_version("2019-08-30T05:23:46+0000");
  script_tag(name:"last_modification", value:"2019-08-30 05:23:46 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-30 04:57:13 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-11494", "CVE-2019-11499");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.3.0 < 2.3.6 Multiple DoS vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to multiple denial of service vulnerabilities in
  submission-login.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot versions 2.3.0 - 2.3.5.2.");

  script_tag(name:"solution", value:"Update to version 2.3.6 or later.");

  script_xref(name:"URL", value:"https://dovecot.org/list/dovecot-news/2019-April/000409.html");
  script_xref(name:"URL", value:"https://dovecot.org/list/dovecot-news/2019-April/000410.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "2.3.0", test_version2: "2.3.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
