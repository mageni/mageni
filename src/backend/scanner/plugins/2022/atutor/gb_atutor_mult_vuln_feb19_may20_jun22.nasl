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

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127055");
  script_version("2023-02-10T08:43:24+0000");
  script_tag(name:"last_modification", value:"2023-02-10 08:43:24 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"creation_date", value:"2022-06-22 11:49:35 +0000 (Wed, 22 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 18:15:00 +0000 (Fri, 15 Apr 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-7172", "CVE-2020-23341", "CVE-2021-43498");

  script_name("ATutor <= 2.2.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atutor_detect.nasl");
  script_mandatory_keys("atutor/detected");

  script_tag(name:"summary", value:"Atutor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2019-7172: A stored-self XSS exists in ATutor, allowing an attacker to
  execute HTML or JavaScript code in a Real Name field to /mods/_core/users/admins/my_edit.php.

  - CVE-2020-23341: The vulnerability allows attackers to execute arbitrary web scripts or HTML via
  a crafted payload.

  - CVE-2021-43498: Weak password reset hash in password_reminder.php lead to access control
  vulnerability.");

  script_tag(name:"affected", value:"Atutor version 2.2.4 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor.

  Note: The product is End of Life (EOL) and will not receive updates anymore.");

  script_xref(name:"URL", value:"https://github.com/atutor/ATutor/releases");
  script_xref(name:"URL", value:"https://github.com/atutor/ATutor/issues/164#issuecomment-459317065");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 0 );
