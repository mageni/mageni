###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_format_string_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PHP 'phar_stream_flush' Format String Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902317");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-2950", "CVE-2010-3436", "CVE-2010-4156");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("PHP 'phar_stream_flush' Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2010-2950");
  script_xref(name:"URL", value:"http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to obtain
  sensitive information and possibly execute arbitrary code via a crafted
  phar:// URI.");

  script_tag(name:"affected", value:"PHP version 5.3 through 5.3.3");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in 'stream.c' in the phar extension, which allows attackers to
   obtain sensitive information.

  - An error in 'open_wrappers.c', allow remote attackers to bypass open_basedir
   restrictions via vectors related to the length of a filename.

  - An error in 'mb_strcut()' function in 'Libmbfl', allows context-dependent
   attackers to obtain potentially sensitive information via a large value of
   the third parameter (aka the length parameter).");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.3.4 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to format string
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if( version_in_range( version:phpVer, test_version:"5.3", test_version2:"5.3.3" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.3.4" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );