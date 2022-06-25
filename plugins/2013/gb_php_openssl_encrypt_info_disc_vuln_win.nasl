###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_openssl_encrypt_info_disc_vuln_win.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# PHP 'openssl_encrypt()' Function Information Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803164");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2012-6113");
  script_bugtraq_id(57462);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-24 16:39:00 +0530 (Thu, 24 Jan 2013)");
  script_name("PHP 'openssl_encrypt()' Function Information Disclosure Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61413");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/81400");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commitdiff;h=270a406ac94b5fc5cc9ef59fc61e3b4b95648a3e");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information from process memory by providing zero bytes of input data.");

  script_tag(name:"affected", value:"PHP version 5.3.9 through 5.3.13 on Windows");

  script_tag(name:"insight", value:"The flaw is due to error in 'openssl_encrypt()' function when handling empty
  $data strings which will allow an attacker to gain access to arbitrary pieces
  of information in current memory.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to information
  disclosure vulnerability");

  script_tag(name:"solution", value:"Apply the patch or upgrade to the latest version from the references.

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_in_range(version:phpVer, test_version:"5.3.9", test_version2:"5.3.13")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.14");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
