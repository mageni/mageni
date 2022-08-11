###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freetype_dos_vuln_win.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# FreeType 2 DoS Vulnerability (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113115");
  script_version("$Revision: 12045 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-16 12:00:00 +0100 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-6942");

  script_name("FreeType 2 DoS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_freetype_detect_win.nasl");
  script_mandatory_keys("FreeType/Win/Ver");

  script_tag(name:"summary", value:"FreeType 2 is prone to a Denial of Service vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target system.");
  script_tag(name:"insight", value:"An issue was discovered in FreeType 2. A NULL pointer dereference in the Ins_GETVARIATION() function within ttinterp.c could lead to DoS via a crafted font file.");
  script_tag(name:"affected", value:"FreeType 2 through version 2.9.");
  script_tag(name:"solution", value:"Update to version 2.9.1 or later.");

  script_xref(name:"URL", value:"https://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=29c759284e305ec428703c9a5831d0b1fc3497ef");
  script_xref(name:"URL", value:"https://download.savannah.gnu.org/releases/freetype/");

  exit(0);
}

CPE = "cpe:/a:freetype:freetype";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.0.0.0", test_version2: "2.9.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.1" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
