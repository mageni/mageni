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

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112843");
  script_version("2020-11-24T11:29:26+0000");
  script_tag(name:"last_modification", value:"2020-11-24 11:49:00 +0000 (Tue, 24 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-24 10:23:11 +0000 (Tue, 24 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2020-1778");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS 8.0.x < 8.0.10 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"summary", value:"OTRS is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When OTRS uses multiple backends for user authentication (with LDAP),
  agents are able to login even if the account is set to invalid.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker in an adjacent network
  to login via LDAP with an account that is set to invalid.");

  script_tag(name:"affected", value:"OTRS 8.0.x - 8.0.9.");

  script_tag(name:"solution", value:"Update to version 8.0.10 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2020-16/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
