###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_fpm_privilege_escalation_vuln.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# PHP 'FastCGI Process Manager' Privilege Escalation Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804290");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2014-0185");
  script_bugtraq_id(67118);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-05-08 14:42:30 +0530 (Thu, 08 May 2014)");
  script_name("PHP 'FastCGI Process Manager' Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone to privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'sapi/fpm/fpm/fpm_unix.c' within FastCGI Process
  Manager that sets insecure permissions for a unix socket.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to the
  socket and gain elevated privileges.");

  script_tag(name:"affected", value:"PHP versions 5.4.x before 5.4.28 and 5.5.x before 5.5.12.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.4.28 or 5.5.12 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q2/192");
  script_xref(name:"URL", value:"http://www.php.net/archive/2014.php#id2014-05-01-1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/04/29/5");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_in_range(version:phpVer, test_version:"5.4.0", test_version2:"5.4.27")||
   version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.11")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.28/5.5.12");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
