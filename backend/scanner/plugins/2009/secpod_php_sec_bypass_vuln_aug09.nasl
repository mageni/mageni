###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sec_bypass_vuln_aug09.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP Security Bypass Vulnerability - Aug09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900835");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7002");
  script_bugtraq_id(31064);
  script_name("PHP Security Bypass Vulnerability - Aug09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/383831.php");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/31064.php");

  script_tag(name:"impact", value:"Successful exploitation will let the local attacker execute arbitrary code and
  can bypass security restriction in the context of the web application.");

  script_tag(name:"affected", value:"PHP version 5.2.5");

  script_tag(name:"insight", value:"Error exists when application fails to enforce 'safe_mode_exec_dir' and
  'open_basedir' restrictions for certain functions, which can be caused via
  the exec, system, shell_exec, passthru, or popen functions, possibly
  involving pathnames such as 'C:' drive notation.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.3.2 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to Security Bypas vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_is_equal( version:phpVer, test_version:"5.2.5" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.3.2" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );