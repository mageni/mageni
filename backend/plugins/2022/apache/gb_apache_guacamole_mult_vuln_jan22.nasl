# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:guacamole";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147402");
  script_version("2022-01-12T03:09:12+0000");
  script_tag(name:"last_modification", value:"2022-01-12 11:02:51 +0000 (Wed, 12 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-12 03:00:41 +0000 (Wed, 12 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2021-41767", "CVE-2021-43999");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Guacamole < 1.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_guacamole_http_detect.nasl");
  script_mandatory_keys("apache/guacamole/detected");

  script_tag(name:"summary", value:"Apache Guacamole is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-41767: Incorrect include of a private tunnel identifier in the non-private details of
  some REST responses. This may allow an authenticated user who already has permission to access a
  particular connection to read from or interact with another user's active use of that same
  connection.

  - CVE-2021-43999: Improper validatation of responses received from a SAML identity provider. If
  SAML support is enabled, this may allow a malicious user to assume the identity of another
  Guacamole user.");

  script_tag(name:"affected", value:"Apache Guacamole version 1.3.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/11/6");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/01/11/7");

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

if (version_is_less(version: version, test_version: "1.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
