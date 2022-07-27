###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_dba_replace_dos_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP dba_replace Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900925");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-7068");
  script_bugtraq_id(33498);
  script_name("PHP dba_replace Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47316");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/498746/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  corrupt files and cause denial of service.");

  script_tag(name:"affected", value:"PHP 4.x and 5.2.6 on all running platform.");

  script_tag(name:"insight", value:"An error occurs in 'dba_replace()' function while processing malformed
  user supplied data containing a key with the NULL byte.");

  script_tag(name:"solution", value:"Upgrade to version 5.2.7 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Denial of Service
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

if( phpVer =~ "^4\." || version_is_equal( version:phpVer, test_version:"5.2.6" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.7" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );