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

CPE = "cpe:/a:openldap:openldap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147068");
  script_version("2021-11-02T05:28:10+0000");
  script_tag(name:"last_modification", value:"2021-11-02 05:28:10 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-02 05:17:37 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2012-1164");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP < 2.4.30 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"slapd allows remote attackers to cause a denial of service
  (assertion failure and daemon exit) via an LDAP search query with attrsOnly set to true, which
  causes empty attributes to be returned.");

  script_tag(name:"affected", value:"OpenLDAP prior to version 2.4.30.");

  script_tag(name:"solution", value:"Update to version 2.4.30 or later.");

  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=7143");

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

if (version_is_less(version: version, test_version: "2.4.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
