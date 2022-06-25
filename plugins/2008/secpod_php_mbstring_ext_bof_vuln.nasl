###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_mbstring_ext_bof_vuln.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# PHP Heap-based buffer overflow in 'mbstring' extension
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
  script_oid("1.3.6.1.4.1.25623.1.0.900185");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5557");
  script_bugtraq_id(32948);
  script_name("PHP Heap-based buffer overflow in 'mbstring' extension");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=45722");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0477.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code via
  a crafted string containing an HTML entity.");

  script_tag(name:"affected", value:"PHP version 4.3.0 to 5.2.6 on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to error in mbfilter_htmlent.c file in the mbstring
  extension. These can be exploited via mb_convert_encoding, mb_check_encoding,
  mb_convert_variables, and mb_parse_str functions.");

  script_tag(name:"solution", value:"Upgrade to version 5.2.7 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Buffer Overflow
  vulnerability.");

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

if( version_in_range( version:phpVer, test_version:"4.3.0", test_version2:"5.2.6" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.7" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );