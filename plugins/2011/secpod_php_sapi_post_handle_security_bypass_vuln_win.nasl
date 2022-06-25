###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sapi_post_handle_security_bypass_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# PHP SAPI_POST_HANDLER_FUNC() Security Bypass Vulnerability (Windows)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902606");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2202");
  script_bugtraq_id(48259);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("PHP SAPI_POST_HANDLER_FUNC() Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_php_detect.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44874");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025659");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67999");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=312103");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to delete files from
  the root directory, which may aid in further attacks.");

  script_tag(name:"affected", value:"PHP version prior to 5.3.7");

  script_tag(name:"insight", value:"The flaw is due to an error in 'SAPI_POST_HANDLER_FUNC()' function in
  rfc1867.c when handling files via a 'multipart/form-data' POST request. which
  allows attacker to bypass security restriction.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.3.7 or later.");

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

##To check PHP version prior to 5.3.7
if(version_is_less(version:phpVer, test_version:"5.3.7")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.7");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
