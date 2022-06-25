###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qradar_version.nasl 12780 2018-12-13 02:31:17Z ckuersteiner $
#
# QRadar Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105802");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12780 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-13 03:31:17 +0100 (Thu, 13 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-07-07 16:59:41 +0200 (Thu, 07 Jul 2016)");
  script_name("QRadar Detection");

  script_tag(name:"summary", value:"The script performs SSH  based detection of QRadar");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("qradar/version");
  exit(0);
}

include("host_details.inc");

if( ! version = get_kb_item( "qradar/version" ) ) exit( 0 );

cpe = 'cpe:/a:ibm:qradar_security_information_and_event_manager:' + version;

# example version 7.3.1.20180720020816
register_product( cpe:cpe, location:'ssh' );
report = build_detection_report( app:'QRadar', version:version, install:'ssh', cpe:cpe );
log_message( port:0, data:report );

exit( 0 );
