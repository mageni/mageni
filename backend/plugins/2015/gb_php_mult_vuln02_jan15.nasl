###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln02_jan15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# PHP Multiple Vulnerabilities - 02 - Jan15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805413");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9426");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-07 12:28:06 +0530 (Wed, 07 Jan 2015)");
  script_name("PHP Multiple Vulnerabilities - 02 - Jan15");

  script_tag(name:"summary", value:"This host is installed with PHP and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a free operation
  on a stack-based character array by The apprentice_load function in
  libmagic/apprentice.c in the Fileinfo component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP versions before 5.6.5");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68665");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1031480");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less_equal(version:phpVer, test_version:"5.6.4")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.6.5");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
