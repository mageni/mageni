###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_unserialize_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP 'unserialize()' Function Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.900993");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4418");
  script_name("PHP 'unserialize()' Function Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2009-4418");
  script_xref(name:"URL", value:"http://www.suspekt.org/downloads/POC2009-ShockingNewsInPHPExploitation.pdf");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary PHP
  code and cause denial of service.");

  script_tag(name:"affected", value:"PHP 5.3.0 and prior on all running platform.");

  script_tag(name:"insight", value:"An error in 'unserialize()' function while processing malformed user supplied
  data containing a long serialized string passed via the '__wakeup()' or
  '__destruct()' methods.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_is_less_equal( version:phpVer, test_version:"5.3.0" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"None" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );