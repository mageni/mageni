###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Interscan Web Security Virtual Appliance Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105246");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-07-07T12:34:32+0000");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2015-04-08 10:07:13 +0200 (Wed, 08 Apr 2015)");

  script_name("Trend Micro Interscan Web Security Virtual Appliance Detection (SSH-Login)");

  script_tag(name:"summary", value:"This script performs an SSH based detection of Trend Micro Interscan Web
  Security Virtual Appliance");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("IWSVA/system");
  exit(0);
}

include("host_details.inc");

if( ! system = get_kb_item( "IWSVA/system" ) )
  exit( 0 );

if( "IWSVA" >!< system )
  exit( 0 );

version = "unknown";

port = get_kb_item( "IMSVA/ssh-login/port" );
set_kb_item( name:"trendmicro/IWSVA/detected", value:TRUE );
set_kb_item( name:"trendmicro/IWSVA/ssh-login/port", value:port );

# IWSVA: IWSVA 6.5-SP2_Build_Linux_1548 $Date: 11/04/2015 16:06:48 PM$
match = eregmatch( pattern:"IWSVA ([0-9.]+).*_Build_Linux_([0-9]+)", string:system );

if( ! isnull( match[1] ) ) {
  version = match[1];
  set_kb_item( name:"trendmicro/IWSVA/ssh-login/" + port + "/concluded", value:match[0] );
}

if( ! isnull( match[2] ) )
  build = match[2];

set_kb_item( name:"trendmicro/IWSVA/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"trendmicro/IWSVA/ssh-login/" + port + "/build", value:build );

exit( 0 );

