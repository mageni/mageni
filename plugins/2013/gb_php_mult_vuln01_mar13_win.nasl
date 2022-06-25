###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln01_mar13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# PHP Multiple Vulnerabilities - 01 - Mar13 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803341");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-1172");
  script_bugtraq_id(53403);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-21 16:27:46 +0530 (Thu, 21 Mar 2013)");
  script_name("PHP Multiple Vulnerabilities - 01 - Mar13 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2012-1172");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-1172");

  script_tag(name:"summary", value:"This host is running PHP and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw due to insufficient validation of file-upload implementation in
  rfc1867.c and it does not handle invalid '[' characters in name values.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to retrieve, corrupt or upload
  arbitrary files, or can cause denial of service via corrupted $_FILES indexes.");

  script_tag(name:"affected", value:"PHP version before 5.4.0");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
