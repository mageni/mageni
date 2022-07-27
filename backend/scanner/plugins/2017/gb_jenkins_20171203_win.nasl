###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jenkins_20171203_win.nasl 12761 2018-12-11 14:32:20Z cfischer $
#
# Jenkins 2.93 XSS Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113064");
  script_version("$Revision: 12761 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 15:32:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-12-07 13:24:25 +0100 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_cve_id("CVE-2017-17383");

  script_name("Jenkins 2.93 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins through 2.93 is prone to an XSS vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if the vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An authenticated attacker can use a crafted tool name in a job configuration form to conduct XSS attacks.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to expose other users to malicious code.");
  script_tag(name:"affected", value:"Jenkins through version 2.93");
  script_tag(name:"solution", value:"Please refer to the vendor advisory for a workaround.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2017-12-05/");

  exit(0);
}

CPE = "cpe:/a:jenkins:jenkins";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.93" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Workaround" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
