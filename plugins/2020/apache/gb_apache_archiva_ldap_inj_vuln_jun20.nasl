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

CPE = 'cpe:/a:apache:archiva';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144158");
  script_version("2020-06-23T09:20:13+0000");
  script_tag(name:"last_modification", value:"2020-06-23 09:20:13 +0000 (Tue, 23 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-23 09:15:26 +0000 (Tue, 23 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-9495");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.5 LDAP Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");

  script_tag(name:"summary", value:"Apache Archiva is prone to an LDAP injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By providing special values to the archiva login form an attacker is able to
  retrieve user attribute data from the connected LDAP server. With certain characters it is possible to modify
  the LDAP filter used to query the users on the connected LDAP server. By measuring the response time,
  arbitrary attribute data can be retrieved from LDAP user objects.");

  script_tag(name:"affected", value:"Apache Archiva prior to version 2.2.5.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.5 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/security.html#CVE-2020-9495");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "2.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
