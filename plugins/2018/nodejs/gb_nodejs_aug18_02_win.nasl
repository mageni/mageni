###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nodejs_aug18_02_win.nasl 12308 2018-11-12 03:41:06Z ckuersteiner $
#
# Node.js 10.x < 10.9.0 Unintentional Exposure of Uninitialized Memory (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112363");
  script_version("$Revision: 12308 $");
  script_cve_id("CVE-2018-7166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 04:41:06 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-27 14:37:00 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js 10.x < 10.9.0 Unintentional Exposure of Uninitialized Memory (Windows)");

  script_tag(name:"summary", value:"The host is installed with Node.js and is
  prone to an unintentional exposure of uninitialized memory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is an argument processing flaw that causes Buffer.alloc() to return uninitialized memory.
This method is intended to be safe and only return initialized, or cleared, memory. The third argument specifying encoding can be passed as a number,
this is misinterpreted by Buffer's internal 'fill' method as the start to a fill operation.

This flaw may be abused where Buffer.alloc()
arguments are derived from user input to return uncleared memory blocks that may contain sensitive information.");

  script_tag(name:"affected", value:"Node.js version 10.x prior to 10.9.0.");

  script_tag(name:"solution", value:"Upgrade to Node.js 10.9.0.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/august-2018-security-releases");
  script_xref(name:"URL", value:"https://nodejs.org");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_win.nasl");
  script_mandatory_keys("Nodejs/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:nodejs:node.js";

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version =~ "^10\." && version_is_less( version:version, test_version:"10.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.9.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
