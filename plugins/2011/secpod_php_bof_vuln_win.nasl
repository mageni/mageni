###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_bof_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP 'socket_connect()' Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902436");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1938");
  script_bugtraq_id(47950);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'socket_connect()' Buffer Overflow Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/May/472");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101665/cve20111938.txt");
  script_xref(name:"URL", value:"http://www.bugsearch.net/en/11873/php-535-socketconnect-buffer-overflow-vulnerability-cve-2011-1938.html?ref=3");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code or to cause denial of service condition.");

  script_tag(name:"affected", value:"PHP Version 5.3.5 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'socket_connect()' function
  within socket module. It uses memcpy to copy path from addr to s_un without
  checking addr length in case when AF_UNIX socket is used.");

  script_tag(name:"solution", value:"Upgrade to version 5.3.7 or later.");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to stack buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less_equal(version:phpVer, test_version:"5.3.5")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.7");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
