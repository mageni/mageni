###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_bamboo_rce_vuln1.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Atlassian Bamboo Remote Code Execution
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
  script_oid("1.3.6.1.4.1.25623.1.0.113012");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-11 10:01:18 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-6576");

  script_name("Atlassian Bamboo Remote Code Execution");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Bamboo 2.2 before 5.8.5 and 5.9.x before 5.9.7 allows remote attackers with access to the Bamboo web interface to execute arbitrary Java code via an unspecified resource.");
  script_tag(name:"vuldetect", value:"Checks if the vulnerable version is present on the host.");
  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to execute arbitrary Java code on the host and possibly gain control over it.");
  script_tag(name:"affected", value:"Atlassian Bamboo versions 2.2 through 5.8.4 and 5.9.x before 5.9.7");
  script_tag(name:"solution", value:"Update to version 5.8.5 or version 5.9.7 respectively.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-16439");
  script_xref(name:"URL", value:"https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2015-10-21-785452575.html");

  exit(0);
}

CPE = "cpe:/a:atlassian:bamboo";

include( "host_details.inc" );
include( "version_func.inc" );

if( !port = get_app_port( cpe: CPE ) ) {
  exit( 0 );
}

if( !version = get_app_version( cpe: CPE, port: port ) ) {
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.2", test_version2: "5.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.8.5" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "5.9.0", test_version2: "5.9.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.7" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
