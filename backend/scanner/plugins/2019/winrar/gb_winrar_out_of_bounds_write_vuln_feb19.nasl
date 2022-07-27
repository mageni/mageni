# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113349");
  script_version("$Revision: 14017 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 12:40:47 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-06 12:37:03 +0200 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20253");

  script_name("WinRAR <= 5.60 Out-of-Bounds Write Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");

  script_tag(name:"summary", value:"WinRAR is prone to an Out-of-Bounds Write Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability can be exploited by bringing a user to parse a specially
  crafted LHA or LZH archive.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code
  in the context of the current user.");
  script_tag(name:"affected", value:"WinRAR through version 5.60.");
  script_tag(name:"solution", value:"Update to version 5.61.");

  script_xref(name:"URL", value:"https://www.win-rar.com/whatsnew.html");

  exit(0);
}

CPE = "cpe:/a:rarlab:winrar";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) {
  CPE = "cpe:/a:rarlab:winrar:x64";
  if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );
}

if( version_is_less( version: version, test_version: "5.61" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.61" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
