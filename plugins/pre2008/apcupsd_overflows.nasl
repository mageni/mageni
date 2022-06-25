# OpenVAS Vulnerability Test
# $Id: apcupsd_overflows.nasl 14243 2019-03-17 19:29:05Z cfischer $
# Description: apcupsd overflows
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:apc:apcupsd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80014");
  script_version("$Revision: 14243 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 20:29:05 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(2070, 6828, 7200);
  script_cve_id("CVE-2001-0040", "CVE-2003-0098", "CVE-2003-0099");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("apcupsd < 3.8.6 / 3.10.x < 3.10.5 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
  script_family("Gain a shell remotely");
  script_dependencies("apcnisd_detect.nasl");
  script_mandatory_keys("apcupsd/detected");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"summary", value:"The remote apcupsd, according to its version number,
  is vulnerable to multiple vulnerabilities.");

  script_tag(name:"affected", value:"Versions before 3.8.6, and 3.10.x before 3.10.5.");

  script_tag(name:"solution", value:"Update to version 3.8.6, 3.10.5 or later.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  CVE-2001-0040: APC UPS daemon, apcupsd, saves its process ID in a world-writable file.

  CVE-2003-0098: Unknown vulnerability possibly via format strings in a request to a slave server.

  CVE-2003-0099: Multiple buffer overflows related to usage of the vsprintf function.");

  script_tag(name:"impact", value:"CVE-2001-0040: allows local users to kill an arbitrary process by
  specifying the target process ID in the apcupsd.pid file.

  CVE-2003-0098: allows remote attackers to gain root privileges.

  CVE-2003-0099: may allow attackers to cause a denial of service or execute arbitrary code.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( port:port, cpe:CPE ) )
  exit( 0 );

if( version_is_less( installed_version:vers, test_version:"3.8.6" ) )
  fix = "3.8.6";
else if( vers =~ "^3\.10\." && version_is_less( installed_version:vers, test_version:"3.10.5" ) )
  fix = "3.10.5";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );