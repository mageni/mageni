###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_symlink_attack_vuln_win.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# PHP Symlink Attack Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809735");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2014-3981");
  script_bugtraq_id(67837);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-01 17:38:59 +0530 (Thu, 01 Dec 2016)");
  script_name("PHP Symlink Attack Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to symlink attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insecure temporary file
  use in the configure script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows local
  users to overwrite arbitrary files via a symlink attack on the
  '/tmp/phpglibccheck' file.");

  script_tag(name:"affected", value:"PHP versions 5.5.x before 5.5.14, 5.4.x
  before 5.4.30, 5.3.x before 5.3.29 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 5.5.14 or 5.4.30
  or 5.3.29 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67390");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/21");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)){
  exit(0);
}

if(phpVer =~ "^5\.")
{
  if(version_in_range(version:phpVer, test_version:"5.3",test_version2:"5.3.28"))
  {
    VULN = TRUE;
    fix = "5.3.29";
  }

  else if(version_in_range(version:phpVer, test_version:"5.4",test_version2:"5.4.29"))
  {
    VULN = TRUE;
    fix = "5.4.30";
  }

  else if(version_in_range(version:phpVer, test_version:"5.5",test_version2:"5.5.13"))
  {
    VULN = TRUE;
    fix = "5.5.14";
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
    security_message( data:report, port:phpPort );
    exit(0);
  }
}
exit( 99 );
