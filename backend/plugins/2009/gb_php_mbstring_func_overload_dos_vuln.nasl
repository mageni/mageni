###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mbstring_func_overload_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP 'mbstring.func_overload' DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800373");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0754");
  script_bugtraq_id(33542);
  script_name("PHP 'mbstring.func_overload' DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=27421");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479272");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to crash an affected web server.");

  script_tag(name:"affected", value:"PHP version 4.4.4 and prior

  PHP 5.1.x to 5.1.6

  PHP 5.2.x to 5.2.5");

  script_tag(name:"insight", value:"This bug is due to an error in 'mbstring.func_overload' setting in .htaccess
  file. It can be exploited via modifying behavior of other sites hosted on
  the same web server which causes this setting to be applied to other virtual
  hosts on the same server.");

  script_tag(name:"solution", value:"Update to version 4.4.5, 5.1.7, 5.2.6 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_is_less_equal( version:phpVer, test_version:"4.4.4" ) ||
    version_in_range( version:phpVer, test_version:"5.1", test_version2:"5.1.6" ) ||
    version_in_range( version:phpVer, test_version:"5.2", test_version2:"5.2.5" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"4.4.5/5.1.7/5.2.6" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );