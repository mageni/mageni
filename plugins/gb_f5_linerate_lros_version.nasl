###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_linerate_lros_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# F5 LineRate LROS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105304");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-24 13:13:10 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 LineRate LROS Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of F5 LineRate LROS");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("f5/LROS/show_version");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

infos = get_kb_item( "f5/LROS/show_version" );

if( "F5 Networks LROS" >!< infos ) exit( 0 );

cpe = 'cpe:/a:f5:linerate';
vers = 'unknown';

version = eregmatch( pattern:'F5 Networks LROS Version ([0-9.]+[^\r\n ]+)', string:infos );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

report = 'Detected F5 LineRate LROS  (ssh)\n' +
         'Version: ' + vers + '\n';

log_message( port:0, data: report );
exit( 0 );

