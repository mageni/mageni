###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sec_bypass_n_file_write_vuln_900184.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# PHP Security Bypass and File Writing Vulnerability - Dec08
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900184");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658");
  script_bugtraq_id(32383, 32625, 32688);
  script_name("PHP Security Bypass and File Writing Vulnerability - Dec08");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.7");
  script_xref(name:"URL", value:"http://www.php.net/archive/2008.php#id2008-12-07-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/498985/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to write arbitrary file,
  bypass security restrictions and cause directory traversal attacks.");

  script_tag(name:"affected", value:"PHP versions prior to 5.2.7.");

  script_tag(name:"insight", value:"The flaw is due to,

  - An error in initialization of 'page_uid' and 'page_gid' global variables
  for use by the SAPI 'php_getuid' function, which bypass the safe_mode
  restrictions.

  - When 'safe_mode' is enabled through a 'php_admin_flag' setting in
  'httpd.conf' file, which does not enforce the 'error_log', 'safe_mode
  restrictions.

  - In 'ZipArchive::extractTo' function which allows attacker to write files
  via a ZIP file.");

  script_tag(name:"solution", value:"Upgrade to version 5.2.7 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Security Bypass and File
  Writing vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_in_range( version:phpVer, test_version:"5.0", test_version2:"5.2.6" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.7" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );