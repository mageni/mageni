###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_out_of_bounds_read_vuln01_mar16_win.nasl 2016-03-01 16:56:54Z March$
#
# PHP Out of Bounds Read Memory Corruption Vulnerability - 01 - Mar16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807089");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-1903");
  script_bugtraq_id(79916);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 16:56:54 +0530 (Tue, 01 Mar 2016)");
  script_name("PHP Out of Bounds Read Memory Corruption Vulnerability - 01 - Mar16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to out-of-bounds read memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to memory corruption
  vulnerability via a large 'bgd_color' argument to the 'imagerotate' function
  in 'ext/gd/libgd/gd_interpolation.c' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to obtain sensitive information or cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"PHP versions before 5.5.31, 5.6.x before
  5.6.17, and 7.x before 7.0.2 on Windows");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.31, or 5.6.17 or
  7.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70976");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/14/8");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.5.31"))
{
  fix = '5.5.31';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.6")
{
  if(version_is_less(version:phpVer, test_version:"5.6.17"))
  {
    fix = '5.6.17';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^7\.0")
{
  if(version_is_less(version:phpVer, test_version:"7.0.2"))
  {
    fix = '7.0.2';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);