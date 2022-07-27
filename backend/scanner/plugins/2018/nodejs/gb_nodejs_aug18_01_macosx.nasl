###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nodejs_aug18_01_macosx.nasl 12236 2018-11-07 05:34:17Z ckuersteiner $
#
# Node.js < 10.9.0, 8.11.4, 6.14.4 OOB Write Vulnerability (Mac OS X)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112362");
  script_version("$Revision: 12236 $");
  script_cve_id("CVE-2018-12115");
  script_bugtraq_id(105127);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-07 06:34:17 +0100 (Wed, 07 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-27 14:13:00 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Node.js < 10.9.0, < 8.11.4, < 6.14.4 OOB Write Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Node.js and is
  prone to an out-of-bounds write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An OOB write in Buffer can be used to write to memory outside of a Buffer's memory space.
This can corrupt unrelated Buffer objects or cause the Node.js process to crash.

When used with UCS-2 encoding (recognized by Node.js under the names 'ucs2', 'ucs-2', 'utf16le' and 'utf-16le'), Buffer#write() can be abused
to write outside of the bounds of a single Buffer. Writes that start from the second-to-last position of a buffer cause a miscalculation of the maximum length of the input bytes to be written.");

  script_tag(name:"affected", value:"Node.js versions 6.x prior to 6.14.4, 8.x prior to 8.11.4 and 10.x prior to 10.9.0.");

  script_tag(name:"solution", value:"Upgrade to Node.js version 6.14.4, 8.11.4 or 10.9.0 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/august-2018-security-releases");
  script_xref(name:"URL", value:"https://nodejs.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:nodejs:node.js";

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_in_range( version:version, test_version:"6.0", test_version2:"6.14.3" ) ) {
  fix = "6.14.4";
}

if( version_in_range( version:version, test_version:"8.0", test_version2:"8.11.3" ) ) {
  fix = "8.11.4";
}

if( version =~ "^10\." && version_is_less( version:version, test_version:"10.9.0" ) ) {
  fix = "10.9.0";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
