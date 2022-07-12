###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_imap_do_open_dos_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801583");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2010-4150");
  script_bugtraq_id(44980);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP version 5.2 before 5.2.15 and 5.3 before 5.3.4");

  script_tag(name:"insight", value:"The flaw is due to an erron in 'imap_do_open' function in the IMAP
  extension 'ext/imap/php_imap.c'.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.2.15 or 5.3.4");

  script_tag(name:"summary", value:"This host is running PHP and is prone to denial of service
  vulnerability.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/63390");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=305032");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_in_range(version:phpVer, test_version:"5.2", test_version2:"5.2.14") ||
   version_in_range(version:phpVer, test_version:"5.3", test_version2:"5.3.3")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.2.15/5.3.4");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
