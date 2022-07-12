###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_crypt_func_sec_bypass_vuln_win.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# PHP 'crypt()' Function Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802329");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2011-3189");
  script_bugtraq_id(48259);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("PHP 'crypt()' Function Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45678");
  script_xref(name:"URL", value:"http://www.php.net/archive/2011.php#id2011-08-22-1");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass authentication
  via an arbitrary password.");

  script_tag(name:"affected", value:"PHP version 5.3.7 on Windows");

  script_tag(name:"insight", value:"The flaw is due to an error in 'crypt()' function which returns the
  salt value instead of hash value when executed with MD5 hash, which allows
  attacker to bypass authentication via an arbitrary password.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.3.8 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

##To check PHP version equal to 5.3.7
if(version_is_equal(version:phpVer, test_version:"5.3.7")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.8");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
