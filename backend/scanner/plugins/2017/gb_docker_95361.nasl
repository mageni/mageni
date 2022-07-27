###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docker_95361.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Docker Local Privilege Escalation Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:docker:docker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140120");
  script_bugtraq_id(95361);
  script_cve_id("CVE-2016-9962");
  script_version("$Revision: 12106 $");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Docker Local Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95361");
  script_xref(name:"URL", value:"https://www.docker.com/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jan/21");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to gain elevated privileges.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to 1.12.6 or newer");
  script_tag(name:"summary", value:"Docker is prone to a local privilege-escalation vulnerability.");
  script_tag(name:"affected", value:"Versions prior to Docker 1.12.6 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-11 17:15:30 +0100 (Wed, 11 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_docker_remote_detect.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version =  get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"1.12.6" ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"1.12.6" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
