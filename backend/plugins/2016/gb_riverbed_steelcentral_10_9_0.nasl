###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_riverbed_steelcentral_10_9_0.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Riverbed SteelCentral NetProfiler & NetExpress Virtual Editions Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:riverbed:steelcentral";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105790");
  script_version("$Revision: 12363 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Riverbed SteelCentral NetProfiler & NetExpress Virtual Editions Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Riverbed-SteelCentral-NetProfilerNetExpress-Advisory.pdf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to 10.9.0 or newer");
  script_tag(name:"summary", value:"The Riverbed SteelCentral NetProfiler and NetExpress virtual appliances are vulnerable to multiple vulnerabilities, including authentication bypass, SQL injection,
arbitrary code execution via command injection, privilege escalation, local file inclusion, cross-site scripting, account hijackingand hardcoded default credentials.");
  script_tag(name:"affected", value:"SteelCentral NetProfiler <= 10.8.7 & SteelCentral NetExpress <= 10.8.7");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-30 17:13:33 +0200 (Thu, 30 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_riverbed_steelcentral_version.nasl");
  script_mandatory_keys("riverbed/SteelCentral/installed", "riverbed/SteelCentral/is_vm", "riverbed/SteelCentral/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! get_kb_item("riverbed/SteelCentral/is_vm") ) exit( 0 );
if( ! model = get_kb_item( "riverbed/SteelCentral/model" ) ) exit( 0 );

if( model !~ '^SCNE' && model !~ '^SCNP' ) exit( 99 );

if( vers = get_app_version( cpe:CPE, service:'consolidated_version' ) )
{
  if( version_is_less( version: vers, test_version: "10.9.0" ) )
  {
      report = report_fixed_ver( installed_version:vers, fixed_version:'10.9.0' );
      security_message( data:report );
      exit (0 );
  }

}

exit( 0 );
