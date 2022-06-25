###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_mult_dos_vuln_win.nasl 9193 2018-03-23 15:15:44Z cfischer $
#
# GraphicsMagick 1.3.26 Multiple DoS Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113137");
  script_version("$Revision: 9193 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-23 16:15:44 +0100 (Fri, 23 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-15 14:01:02 +0100 (Thu, 15 Mar 2018)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231");

  script_name("GraphicsMagick 1.3.26 Multiple DoS Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");

  script_tag(name:"summary", value:"GraphicsMagick is prone to multiple Denial of Service vulnerabilities, exploitable via specially crafted files.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  An allocation failure vulnerability was found in the function ReadTIFFImage in coders/tiff.c, which allows attackers to cause a denial of service via a crafted file, because file size is not properly used to restrict scanline, strip, and tile allocations.

  A NULL pointer dereference vulnerability was found in the function ReadCINEONImage in coders/cineon.c, which allows attackers to cause a denial of service via a crafted file.

  A NULL pointer dereference vulnerability was found in the function ReadEnhMetaFile in coders/emf.c, which allows attackers to cause a denial of service via a crafted file.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash GraphicsMagick.");
  script_tag(name:"affected", value:"GraphicsMagick through version 1.3.26.");
  script_tag(name:"solution", value:"Update to version 1.3.27 or above.");

  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/461/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/473/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/graphicsmagick/bugs/475/");

  exit( 0 );
}

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.3.27" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.3.27" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
