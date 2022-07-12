###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyfaq_mult_vuln_sep18.nasl 12408 2018-11-19 09:34:54Z asteins $
#
# phpmyFAQ <= 2.9.10 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113266");
  script_version("$Revision: 12408 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 10:34:54 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-11 10:48:56 +0200 (Tue, 11 Sep 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16650", "CVE-2018-16651");

  script_name("phpmyFAQ <= 2.9.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"phpMyFAQ does not implement sufficient checks to avoid CSRF and CSV injection for the reports generated in the admin backend.
  For the CSRF and CSV injection, an attacker needs administrator privileges to be executed.");
  script_tag(name:"affected", value:"phpMyFAQ through version 2.9.10.");
  script_tag(name:"solution", value:"Update to version 2.9.11.");

  script_xref(name:"URL", value:"https://www.phpmyfaq.de/security/advisory-2018-09-02");

  exit(0);
}

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.9.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
