###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_mult_vuln_jun18.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Centreon Web <= 2.8.23 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113217");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-27 10:30:30 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11587", "CVE-2018-11588", "CVE-2018-11589");

  script_name("Centreon <= 2.8.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");

  script_tag(name:"summary", value:"Centreon Web is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Remote Code Execution vulnerability via the 'RPN' value
    in the Virtual Metric form in centreonGraph.class.php.

  - Multiple SQL injection vulnerabilities via the searchU parameter in viewLogs.php,
    the id parameter in GetXMLHost.php, the chartId parameter in ExportCSVServiceData.php,
    the searchCurve parameter in listComponentTemplates.php
    and the host_id parameter in makeXML_ListMetrics.php

  - An authenticated user may inject a payload into the username or command description,
    resulting in stored XSS.");
  script_tag(name:"affected", value:"Centreon Web through version 2.8.23.");
  script_tag(name:"solution", value:"Update to version 2.8.24.");

  script_xref(name:"URL", value:"https://documentation.centreon.com/docs/centreon/en/latest/release_notes/centreon-2.8/centreon-2.8.24.html");

  exit(0);
}

CPE = "cpe:/a:centreon:centreon";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.8.24" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.24" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
