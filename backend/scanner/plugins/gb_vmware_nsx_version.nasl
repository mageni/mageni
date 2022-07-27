###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_nsx_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Vmware NSX Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105422");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-27 15:23:03 +0100 (Tue, 27 Oct 2015)");
  script_name("Vmware NSX Version Detection");

  script_tag(name:"summary", value:"This script detect the Vmware NSX Version through SSH or HTTP-API");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "gb_vmware_nsx_version_api.nasl");
  script_mandatory_keys("vmware_nsx/detected_by");
  exit(0);
}


include("host_details.inc");

cpe = 'cpe:/a:vmware:nsx';

detected_by = get_kb_item( "vmware_nsx/detected_by" );
if( ! detected_by ) exit( 0 );

if( detected_by == "HTTP-API" )
{
  version = get_kb_item("vmware_nsx/http_api/version");
  build   = get_kb_item("vmware_nsx/http_api/build");

  if( ! version ) exit( 0 );

}
else if( detected_by == "SSH" )
{
  show_ver = get_kb_item("vmware_nsx/show_ver");
  _version = eregmatch( pattern:'System Version:[ ]+([0-9]+\\.[^\r\n ]+)', string: show_ver );
  if( isnull( _version[1] ) ) exit( 0 );

  vb = split( _version[1], sep:'-', keep:FALSE );
  if( isnull(vb[0] ) || isnull( vb[1] ) ) exit( 0 );

  version = vb[0];
  build = vb[1];

}
else
 exit( 0 );

if( ! version ) exit( 0 );
cpe += ':' + version;

set_kb_item( name:"vmware_nsx/version", value:version );

app = 'Vmware NSX';
report_version = version;


if( build )
{
  set_kb_item( name:"vmware_nsx/build", value:build );
  report_version += '-' + build;
}

register_product( cpe:cpe, location:detected_by );

log_message( data: build_detection_report( app:app,
                                           version:report_version,
                                           install:detected_by,
                                           cpe:cpe,
                                           concluded: detected_by ),
             port:0 );

exit( 0 );

