###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_mult_vuln_lin_1114.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Cacti 1.1.27 multiple vulnerabilities (Linux)
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113050");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-14 12:30:30 +0100 (Tue, 14 Nov 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-16785", "CVE-2017-16660", "CVE-2017-16661");

  script_name("Cacti 1.1.27 multiple vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti through 1.1.27 is prone to following vulnerabilities:

  - Reflected XSS

  - Authenticated information disclosure

  - Authenticated remote code execution");
  script_tag(name:"vuldetect", value:"The script checks if the vulnerable version is present on the host.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated administrator to run arbitrary code on the host.");
  script_tag(name:"affected", value:"Cacti through version 1.1.27");
  script_tag(name:"solution", value:"Update Cacti to 1.1.28");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/1066");

  exit(0);
}

CPE = "cpe:/a:cacti:cacti";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.1.28" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.28" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
