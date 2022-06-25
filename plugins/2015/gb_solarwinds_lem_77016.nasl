###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_lem_77016.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# SolarWinds Log and Event Manager Command Injection Vulnerability
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

CPE = "cpe:/a:solarwinds:log_and_event_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105450");
  script_bugtraq_id(77016, 77118);
  script_cve_id("CVE-2015-7839", "CVE-2015-7840");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("SolarWinds Log and Event Manager Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77016");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands. Failed exploit attempts will result in a denial-of-service condition.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The ping feature is subject to command injection. Specifically, by entering crafted text in response to the prompts, it is possible to open a bash shell allowing the execution
of arbitrary commands and code.

The second flaw exists within requests to /services/messagebroker/nonsecurestreamingamf utilizing the traceroute functionality. A command injection vulnerability exists which allows an attacker to execute arbitrary commands");
  script_tag(name:"solution", value:"Upgrade to SolarWinds Log and Event Manager version 6.2.0 or later.");
  script_tag(name:"summary", value:"SolarWinds Log and Event Manager is prone to a command-injection vulnerability.");
  script_tag(name:"affected", value:"SolarWinds Log and Event Manager < 6.2.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-13 11:00:23 +0100 (Fri, 13 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_solarwinds_log_event_manager_version.nasl");
  script_mandatory_keys("solarwinds_lem/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"6.2.0" ) )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     6.2.0';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

