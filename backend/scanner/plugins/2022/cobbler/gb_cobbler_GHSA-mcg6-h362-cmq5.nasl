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

CPE = "cpe:/a:cobbler_project:cobbler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147788");
  script_version("2022-03-14T04:31:10+0000");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-14 04:28:24 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_cve_id("CVE-2022-0860");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cobbler < 3.3.2 Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cobbler_http_detect.nasl");
  script_mandatory_keys("cobbler/detected");

  script_tag(name:"summary", value:"Cobbler is prone to an improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If PAM is correctly configured and a user account is set to
  expired, the expired user-account is still able to successfully log into Cobbler in all places
  (Web UI, CLI & XMLRPC-API).

  The same applies to user accounts with passwords set to be expired.");

  script_tag(name:"affected", value:"Cobbler version 3.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 3.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/cobbler/cobbler/security/advisories/GHSA-mcg6-h362-cmq5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
