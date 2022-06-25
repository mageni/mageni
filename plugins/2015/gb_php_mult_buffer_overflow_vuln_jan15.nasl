###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_buffer_overflow_vuln_jan15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# PHP Multiple Buffer Overflow Vulnerabilities - Jan15
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
  script_oid("1.3.6.1.4.1.25623.1.0.805410");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8626");
  script_bugtraq_id(70928);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-06 17:55:40 +0530 (Tue, 06 Jan 2015)");
  script_name("PHP Multiple Buffer Overflow Vulnerabilities - Jan15");

  script_tag(name:"summary", value:"This host is installed with PHP and is
  prone to denial of service and arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to

  - Improper validation of user supplied input passed to date_from_ISO8601()
    function in xmlrpc.c

  - including a timezone field in a date, leading to improper XML-RPC
    encoding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"PHP versions 5.2.x before 5.2.7");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.2.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=45226");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/11/06/3");

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

if(phpVer =~ "^5\.2"){
  if(version_in_range(version:phpVer, test_version:"5.2.0", test_version2:"5.2.6")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.2.7");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);
