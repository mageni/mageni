###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_log_event_manager_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SolarWinds Log & Event Manager Detection
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
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105449");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-12 14:21:39 +0100 (Thu, 12 Nov 2015)");
  script_name("SolarWinds Log & Event Manager Detection");

  script_tag(name:"summary", value:"This Script get the via HTTP(s) or SSH detected SolarWinds Log & Event Manager version");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "gb_solarwinds_log_event_manager_web_detect.nasl");
  script_mandatory_keys("solarwinds_lem/installed");
  exit(0);
}

include("host_details.inc");

source = 'SSH';
cpe = 'cpe:/a:solarwinds:log_and_event_manager';

version = get_kb_item("solarwinds_lem/version/ssh");

if( ! version )
{
  version = get_kb_item("solarwinds_lem/version/http");
  source = 'HTTP(s)';
}

if( ! version ) exit( 0 );

cpe += ':' + version;
set_kb_item( name:'solarwinds_lem/version', value:version );

if( source == 'SSH' )
{
  hotfix = get_kb_item("solarwinds_lem/hotfix/ssh");
  if( hotfix )
    set_kb_item( name:'solarwinds_lem/hotfix', value:hotfix );
  else
    set_kb_item( name:'solarwinds_lem/hotfix', value:"0");
}

register_product( cpe:cpe, location:source );

report = 'Detected SolarWinds Log & Event Manager\nVersion: ' + version + '\nCPE: ' + cpe;

if( hotfix ) report += '\nInstalled hotfix: ' + hotfix;

report += '\nDetection source: ' + source;

log_message( port:0, data:report );

exit(0);

