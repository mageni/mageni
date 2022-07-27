###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_lem_hf2.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# SolarWinds Log and Event Manager XML External Entity Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105451");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("SolarWinds Log and Event Manager XML External Entity Injection Vulnerability");

  script_xref(name:"URL", value:"https://thwack.solarwinds.com/docs/DOC-187416");
  script_xref(name:"URL", value:"https://www.ddifrontline.com/ddivrt-2015-55-solarwinds-log-and-event-manager-remote-command-execution/");

  script_tag(name:"impact", value:"his vulnerability can be abused to allow remote execution of arbitrary system commands, which will lead to complete compromise of the LEM appliance and furthermore lead to full control of any connected endpoint agents that may be deployed throughout the enterprise.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"SolarWinds Log and Event Manager (LEM) is vulnerable to an Extensible Markup Language (XML) external entity injection through the agent message processing service. This service listens on TCP port 37891. Using a crafted XML message, an attacker can trigger the vulnerability and force the disclosure of arbitrary files on the appliance.");
  script_tag(name:"solution", value:"Upgrade to SolarWinds Log and Event Manager version 6.2.0 Hotfix 2 or later.");
  script_tag(name:"summary", value:"SolarWinds Log and Event Manager (LEM) is vulnerable to an Extensible Markup Language (XML) external entity injection");
  script_tag(name:"affected", value:"SolarWinds Log and Event Manager < 6.2.0 Hotfix 2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-13 11:00:23 +0100 (Fri, 13 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_solarwinds_log_event_manager_version.nasl");
  script_mandatory_keys("solarwinds_lem/version", "solarwinds_lem/hotfix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"6.2.0" ) ) vuln = TRUE;

if( version == "6.2.0" )
{
  hotfix = get_kb_item("solarwinds_lem/hotfix");
  if( hotfix )
    if( int( hotfix ) < 2 ) vuln = TRUE;
}

if( vuln )
{
  report = 'Installed version: ' + version + '\n';

  if( hotfix ) report += 'Installed hotfix:  ' + hotfix + '\n';

  report += 'Fixed version:     6.2.0 Hotfix 2';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

