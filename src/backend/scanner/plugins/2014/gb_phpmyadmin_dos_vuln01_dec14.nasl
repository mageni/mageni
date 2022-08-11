###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_dos_vuln01_dec14.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# phpMyAdmin Denial-of-Service Vulnerability -01 Dec14
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805307");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-9218");
  script_bugtraq_id(71434);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-26 15:10:42 +0530 (Fri, 26 Dec 2014)");
  script_name("phpMyAdmin Denial-of-Service Vulnerability -01 Dec14");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin and
  is prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error triggered
  during the handling of long passwords");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the affected application to crash, denying service to
  legitimate users.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.x prior to 4.0.10.7,
  4.1.x prior to 4.1.14.8 and 4.2.x prior to 4.2.13.1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 4.0.10.7 or 4.1.14.8
  or 4.2.13.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://1337day.com/exploit/23007");
  script_xref(name:"URL", value:"http://secunia.com/advisories/60454");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/99140");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-17.php");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! phpPort = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if( version_in_range( version:phpVer, test_version:"4.0.0", test_version2:"4.0.10.6" ) ) {
  fix = "4.0.10.7";
  VULN = TRUE;
}
if( version_in_range( version:phpVer, test_version:"4.1.0", test_version2:"4.1.14.7" ) ) {
  fix = "4.1.14.8";
  VULN = TRUE;
}

if( version_in_range( version:phpVer, test_version:"4.2.0", test_version2:"4.2.13.0" ) ) {
  fix = "4.2.13.1";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:fix );
  security_message( port:phpPort, data:report );
  exit( 0 );
}

exit( 99 );