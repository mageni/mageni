###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_pca_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Prime Collaboration Assurance Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105730");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-25 13:07:14 +0200 (Wed, 25 May 2016)");
  script_name("Cisco Prime Collaboration Assurance Detection");

  script_tag(name:"summary", value:"This script performs ssh based detection of Cisco Prime Collaboration Assurance");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_pca/show_ver");
  exit(0);
}


include("host_details.inc");

show_ver = get_kb_item("cisco_pca/show_ver");

if( ! show_ver || "Cisco Prime Collaboration Assurance" >!< show_ver ) exit( 0 );

cpe = 'cpe:/a:cisco:prime_collaboration_assurance';
vers = 'unknown';

version = eregmatch( pattern:'Cisco Prime Collaboration Assurance\n-+\nVersion\\s*:\\s*([0-9]+[^\r\n]+)', string:show_ver ); # for example: 10.0.0.791
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:'cisco_pca/version', value:vers );
  cpe += ':' + vers;
}

set_kb_item(name: "cisco_pca/detected", value: TRUE);

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:'Cisco Prime Collaboration Assurance',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: show_ver ),
                                           port:0 );

exit( 0 );

