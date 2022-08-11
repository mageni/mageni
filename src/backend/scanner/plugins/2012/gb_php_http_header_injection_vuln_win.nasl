###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_http_header_injection_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# PHP 'main/SAPI.c' HTTP Header Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802966");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-4388", "CVE-2011-1398");
  script_bugtraq_id(55527, 55297);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-24 18:58:41 +0530 (Mon, 24 Sep 2012)");
  script_name("PHP 'main/SAPI.c' HTTP Header Injection Vulnerability");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/02/1");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/07/3");
  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.php.devel/70584");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/09/05/15");
  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2012-4388");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to insert arbitrary
  headers, conduct cross-site request-forgery, cross-site scripting,
  HTML-injection, and other attacks.");

  script_tag(name:"affected", value:"PHP version prior to 5.3.11, PHP version 5.4.x through 5.4.0RC2 on Windows");

  script_tag(name:"insight", value:"The sapi_header_op function in main/SAPI.c in PHP does not properly determine
  a pointer during checks for %0D sequences.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.1 RC1 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to HTTP header injection
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

## To check PHP version
if(version_is_less(version:phpVer, test_version:"5.3.11") ||
   version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.0.rc2")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.11/5.4.1 RC1");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
