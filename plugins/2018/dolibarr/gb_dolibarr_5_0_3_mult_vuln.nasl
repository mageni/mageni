###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_5_0_3_mult_vuln.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr 5.0.3 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113154");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-04-11 13:19:33 +0200 (Wed, 11 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-9838", "CVE-2017-9839");

  script_name("Dolibarr 5.0.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr ERP / CRM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  Dolibarr ERP/CRM is affected by multiple reflected Cross-Site Scripting (XSS) vulnerabilities: index.php
  (leftmenu parameter), core/ajax/box.php (PATH_INFO), product/stats/card.php (type parameter), holiday/list.php
  (month_create, month_start, and month_end parameters), and don/card.php (societe, lastname, firstname, address,
  zipcode, town, and email parameters).

  Dolibarr ERP/CRM is affected by SQL injection in versions before 5.0.4 via product/stats/card.php (type
  parameter).");

  script_tag(name:"affected", value:"Dolibarr through version 5.0.3");
  script_tag(name:"solution", value:"Update to version 5.0.4 or above.");

  script_xref(name:"URL", value:"https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-010");

  exit(0);
}

CPE = "cpe:/a:dolibarr:dolibarr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "5.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
