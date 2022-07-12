###############################################################################
# OpenVAS Vulnerability Test
#
# Artifactory XStream Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
CPE = "cpe:/a:jfrog:artifactory";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103919");
  script_bugtraq_id(64760);
  script_cve_id("CVE-2013-7285");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2019-05-21T14:04:10+0000");

  script_name("Artifactory XStream Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64760");
  script_xref(name:"URL", value:"http://www.jfrog.com/confluence/display/RTF/Artifactory+3.1.1");

  script_tag(name:"last_modification", value:"2019-05-21 14:04:10 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2014-03-13 10:30:44 +0100 (Thu, 13 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_artifactory_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("artifactory/installed");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to execute
arbitrary code in the context of the user running the affected
application.");
  script_tag(name:"vuldetect", value:"Check the installed version.");
  script_tag(name:"insight", value:"Artifactory prior to version 3.1.1.1 using a XStream library
which is prone to a remote code execution vulnerability.");
  script_tag(name:"solution", value:"Update to Artifactory 3.1.1.1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Artifactory is prone to a remote code-execution vulnerability.");
  script_tag(name:"affected", value:"Artifactory < 3.1.1.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE) ) exit( 0 );
if( vers = get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less( version: vers, test_version: "3.1.1.1" ) )
  {
      report = 'Installed version: ' + vers + '\nFixed version:     3.1.1.1';

      security_message( port:port, data:report );
      exit(0);
  }
}

exit(0);
