###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpmyadmin_37826.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# phpMyAdmin Insecure Temporary File and Directory Creation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100450");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-18 11:34:48 +0100 (Mon, 18 Jan 2010)");
  script_bugtraq_id(37826);
  script_cve_id("CVE-2008-7251", "CVE-2008-7252");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("phpMyAdmin Insecure Temporary File and Directory Creation Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37826");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/index.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-1.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-2.php");

  script_tag(name:"summary", value:"phpMyAdmin creates temporary directories and files in an insecure way.

  An attacker with local access could potentially exploit this issue to
  perform symbolic-link attacks, overwriting arbitrary files in the
  context of the affected application.");
  script_tag(name:"impact", value:"Successful attacks may corrupt data or cause denial-of-service
  conditions. Other unspecified attacks are also possible.");
  script_tag(name:"affected", value:"This issue affects phpMyAdmin 2.11.x (prior to 2.11.10.)");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.11.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );