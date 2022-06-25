###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_stack_consumption_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# PHP 'filter_var()' function Stack Consumption Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801547");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-3710", "CVE-2010-3709");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("PHP 'filter_var()' function Stack Consumption Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=52929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=646684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514562/30/150/threaded");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to
  cause a denial of service (memory consumption and application crash)
  via a long e-mail address string.");

  script_tag(name:"affected", value:"PHP version 5.2 through 5.2.14 and 5.3 through 5.3.3");

  script_tag(name:"insight", value:"- The flaw exists due to an error in 'filter_var()' function, when
  FILTER_VALIDATE_EMAIL mode is used while processing the long e-mail address string.

  - A NULL pointer dereference vulnerability exists in 'ZipArchive::getArchiveComment'.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.2.15/5.3.4 or later.");

  script_tag(name:"summary", value:"This host is running PHP and is prone to a stack consumption
  vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/downloads.php");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.2", test_version2:"5.2.14" ) ||
    version_in_range( version:vers, test_version:"5.3", test_version2:"5.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.15/5.3.4" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
