###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_display_errors_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# PHP display_errors Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800334");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5814");
  script_name("PHP display_errors Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN50327700/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2008/JVNDB-2008-000084.html");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject arbitrary web script
  or HTML via unspecified vectors and conduct Cross-Site Scripting attacks.");

  script_tag(name:"affected", value:"PHP version 5.2.7 and prior on all running platform.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of certain inputs when
  display_errors settings is enabled.");

  script_tag(name:"solution", value:"Upgrade to version 5.2.8 or later.");

  script_tag(name:"summary", value:"The host is running PHP and is prone to Cross-Site Scripting
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

if( version_is_less_equal( version:phpVer, test_version:"5.2.7" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.8" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );