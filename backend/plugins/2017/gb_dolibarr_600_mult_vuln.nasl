###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_600_mult_vuln.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr Version 6.0.0 is vulnerable to different attacks, like XSS or arbitrary code execution
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113000");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2017-09-19 08:36:42 +0200 (Tue, 19 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-14238", "CVE-2017-14239", "CVE-2017-14240", "CVE-2017-14241", "CVE-2017-14242");

  script_name("Dolibarr CRM Version 6.0.0 multiple vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"This host is running an older version of Dolibarr ERP/CRM and is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist:

  - SQL Injection in admin/menus/edit.php via the menuId parameter

  - SQL Injection in don/list.php via the statut parameter

  - XSS in htdocs/admin/company.php via the (1) CompanyName, (2) CompanyAddress, (3) CompanyZip, (4) CompanyTown, (5) Fax, (6) EMail, (7) Web, (8) ManagingDirectors, (9) Note, (10) Capital, (11) ProfId1, (12) ProfId2, (13) ProfId3, (14) ProfId4, (15) ProfId5, or (16) ProfId6 parameter

  - XSS in htdocs/admin/menus/edit.php via the Title parameter

  - Sensititve information disclosure in document.php via the file parameter");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary HTML and
script code in a user's browser session in the context of a vulnerable site and to cause SQL Injection attacks to
gain sensitive information.");

  script_tag(name:"affected", value:"Dolibarr version 6.0.0");

  script_tag(name:"solution", value:"The vendor has implemented a fix for the vulnerabilities. Please upgrade your software to version 6.0.1.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/commit/d26b2a694de30f95e46ea54ea72cc54f0d38e548");
  script_xref(name:"URL", value:"https://sourceforge.net/projects/dolibarr/files/Dolibarr%20ERP-CRM/");

  exit(0);
}

CPE = "cpe:/a:dolibarr:dolibarr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( !version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_equal( version: version, test_version: "6.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );


