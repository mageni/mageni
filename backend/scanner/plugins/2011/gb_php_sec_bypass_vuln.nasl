###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_sec_bypass_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# PHP 'extract()' Function Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801731");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2011-0752");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("PHP 'extract()' Function Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_15.php");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/12/13/4");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to bypass intended
  access restrictions by modifying data structures that were not intended
  to depend on external input.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.15");

  script_tag(name:"insight", value:"The flaw is due to error in 'extract()' function, it does not prevent
  use of the 'EXTR_OVERWRITE' parameter to overwrite the GLOBALS superglobal array.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.2.15 or later");

  script_tag(name:"summary", value:"This host is running PHP and is prone to security bypass
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

if(version_is_less(version:phpVer, test_version:"5.2.15")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.2.15");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);