###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_apache_req_headers_bof_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# PHP 'apache_request_headers()' Function Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902837");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(53455);
  script_cve_id("CVE-2012-2329");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-23 16:16:16 +0530 (Wed, 23 May 2012)");
  script_name("PHP 'apache_request_headers()' Function Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49014");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53455");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.4.3");
  script_xref(name:"URL", value:"http://www.php.net/archive/2012.php#id2012-05-08-1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=820000");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"PHP Version 5.4.x before 5.4.3 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'apache_request_headers()'
  function, which can be exploited to cause a denial of service via a long
  string in the header of an HTTP request.");

  script_tag(name:"solution", value:"Upgrade to PHP Version 5.4.3 or later.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_in_range(version: phpVer, test_version: "5.4.0", test_version2: "5.4.2")) {
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.3");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
