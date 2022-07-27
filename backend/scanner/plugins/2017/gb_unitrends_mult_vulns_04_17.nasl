###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unitrends_mult_vulns_04_17.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Unitrends Multiple Vulnerabilities
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

CPE = 'cpe:/a:unitrends:enterprise_backup';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140250");
  script_tag(name:"cvss_base", value:"10.0");
  script_cve_id("CVE-2017-7280", "CVE-2017-7284", "CVE-2017-7281", "CVE-2017-7279", "CVE-2017-7282", "CVE-2017-7283");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Unitrends Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://rhinosecuritylabs.com/research/remote-code-execution-bug-hunting-chapter-1/");
  script_xref(name:"URL", value:"https://www.unitrends.com/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Ask vendor for an update.");
  script_tag(name:"summary", value:"Unitrends is  prone to multiple vulnerabilities:

  - RCE in /api/includes/systems.php Unitrends < 9.0.0

  - Forced Password Change Unitrends in /api/includes/users.php < 9.1.2

  - Unrestricted File Upload

  - Privilege Escalation in Unitrends < 9.0.0");

  script_tag(name:"affected", value:"Unitrends < 9.1.2");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-12 16:05:50 +0200 (Wed, 12 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_unitrends_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("unitrends/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"9.1.2" ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"9.1.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
