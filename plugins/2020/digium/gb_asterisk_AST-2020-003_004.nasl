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

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145094");
  script_version("2020-12-23T06:10:00+0000");
  script_tag(name:"last_modification", value:"2020-12-23 06:10:00 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-23 06:04:38 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple DoS Vulnerabilities (AST-2020-003, AST-2020-004)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist in the res_pjsip_diversion module:

  - A crash can occur when a SIP message is received that has a History-Info header, which contains a tel-uri.

  - A crash can occur when a SIP 181 response is received that has a Diversion header, which contains a tel-uri.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.38.0, 16.15.0, 17.9.0 and 18.1.0.");

  script_tag(name:"solution", value:"Upgrade to Version 13.38.1, 16.15.1, 17.9.1, 18.1.1 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2020-003.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2020-004.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "13.38.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.38.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version == "16.15.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.15.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version == "17.9.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.9.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version == "18.1.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.1.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
