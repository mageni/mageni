###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vsphere_data_protection_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# vSphere Data Protection Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140102");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-28 09:34:09 +0100 (Wed, 28 Dec 2016)");
  script_name("vSphere Data Protection Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of vSphere Data Protection");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("vmware/vSphere_Data_Protection/rls");
  exit(0);
}

include("host_details.inc");

if( ! rls = get_kb_item( "vmware/vSphere_Data_Protection/rls" ) ) exit( 0 );

cpe = 'cpe:/a:vmware:vsphere_data_protection';
version ="unknown";

set_kb_item( name:"vmware/vSphere_Data_Protection/installed", value:TRUE );

# <product>vSphere Data Protection 6.1</product>
# <version>6.1.0.173</version>
# <fullVersion>6.1.0.173</fullVersion>
# <vendor>VMware</vendor>
# <vendorUUID/>
# <productRID/>
# <vendorURL>http://www.vmware.com/</vendorURL>
# <productURL/>
# <supportURL/>
# <releaseDate>20150813220343.000000+000</releaseDate>
# <description/>

v = eregmatch( pattern:'<version>([0-9.]+[^<]+)</version>', string:rls );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  set_kb_item( name:"vmware/vSphere_Data_Protection/version", value:version );
}

register_product( cpe:cpe, location:"ssh", service:"ssh" );

report = build_detection_report( app:"vSphere Data Protection", version:version, install:"ssh", cpe:cpe, concluded:v[0] );
log_message( port:0, data:report);

exit( 0 );

