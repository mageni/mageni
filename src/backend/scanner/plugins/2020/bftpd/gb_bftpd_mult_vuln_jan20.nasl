# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113622");
  script_version("2020-01-13T12:10:50+0000");
  script_tag(name:"last_modification", value:"2020-01-13 12:10:50 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-13 11:58:30 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-6162", "CVE-2020-6835");

  script_name("bftpd < 5.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_bftpd_detect.nasl");
  script_mandatory_keys("bftpd/installed");

  script_tag(name:"summary", value:"bftpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Under certain circumstances, an out-of-bounds read is triggered
    due to an uninitialized value. The daemon crashes at startup in
    the hidegroups_init function in dirlist.c.

  - There is a heap-based off-by-one error
    during file-transfer error-checking.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the FTP server
  or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"bftdp through version 5.3.");

  script_tag(name:"solution", value:"Update to version 5.4.");

  script_xref(name:"URL", value:"http://bftpd.sourceforge.net/news.html#302460");
  script_xref(name:"URL", value:"https://fossies.org/linux/bftpd/CHANGELOG");

  exit(0);
}

CPE = "cpe:/a:bftpd:bftpd";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.4", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
