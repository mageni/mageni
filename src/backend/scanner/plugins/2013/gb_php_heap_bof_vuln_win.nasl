###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_heap_bof_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PHP 'phar/tar.c' Heap Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803342");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-2386");
  script_bugtraq_id(47545);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-21 18:05:46 +0530 (Thu, 21 Mar 2013)");
  script_name("PHP 'phar/tar.c' Heap Buffer Overflow Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/426726.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-2386");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  or cause a denial-of-service condition via specially crafted TAR file.");

  script_tag(name:"affected", value:"PHP version before 5.3.14 and 5.4.x before 5.4.4");

  script_tag(name:"insight", value:"Flaw related to overflow in phar_parse_tarfile()function in ext/phar/tar.c
  in the phar extension.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.4 or 5.3.14 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to heap buffer overflow
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.3.14")||
  version_in_range(version:phpVer, test_version:"5.4", test_version2: "5.4.3")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.14/5.4.4");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
