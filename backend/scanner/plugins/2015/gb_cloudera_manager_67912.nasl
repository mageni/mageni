###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudera_manager_67912.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cloudera Manager Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:cloudera:cloudera_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105174");
  script_bugtraq_id(67912);
  script_cve_id("CVE-2014-0220");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 12106 $");

  script_name("Cloudera Manager Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67912");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
may aid in launching further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Cloudera Manager allows remote authenticated users to obtain sensitive configuration information
via the API.");
  script_tag(name:"solution", value:"Udate Cloudera Manager to version 4.8.3/5.0.1 or later.");
  script_tag(name:"summary", value:"Cloudera Manager is prone to an information-disclosure vulnerability.");
  script_tag(name:"affected", value:"Cloudera Manager prior to 4.8.3 and 5.0.0 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-20 17:01:26 +0100 (Tue, 20 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cloudera_manager_detect.nasl");
  script_require_ports("Services/www", 7180);
  script_mandatory_keys("cloudera_manager/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less( version:vers, test_version:"4.8.3" ) )
  {
    fix = "4.8.3";
    VULN = TRUE;
  }

  if( vers =~ "^5\." )
  {
    if( version_is_less( version:vers, test_version:'5.0.1') )
    {
      fix = "5.0.1";
      VULN = TRUE;
    }
  }

  if( VULN )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + fix  + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }

  exit( 99 );
}

exit( 0 );
