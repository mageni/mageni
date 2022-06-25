###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_central_version_ssh.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco UCS Central Detection (SSH)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105571");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-17 12:43:49 +0100 (Thu, 17 Mar 2016)");
  script_name("Cisco UCS Central Detection (SSH)");

  script_tag(name:"summary", value:"'This script performs SSH based version detection of Cisco UCS Central");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  exit(0);
}

include("host_details.inc");

source = "ssh";

show_version = get_kb_item( "cisco/show_version" );

if( ! show_version || "Cisco UCS Central" >!< show_version ) exit( 0 );

cpe = 'cpe:/a:cisco:ucs_central_software';
set_kb_item( name:"cisco_ucs_central/installed", value:TRUE );

sw = split( show_version );

foreach line ( sw )
{
  if( line =~ "^core\s+Base System" )
  {
    version = eregmatch( pattern:"^core\s+Base System\s+([0-9]+[^ ]+)", string:line );
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      cpe += ':' + vers;
      set_kb_item( name:"cisco_ucs_central/" + source + "/version", value:vers );
      break;
    }
  }
}
report = build_detection_report( app:"Cisco UCS Central", version:vers, install:source, cpe:cpe, concluded:"show version" );
log_message( port:0, data:report );

exit( 0 );

