###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filr_version.nasl 13825 2019-02-22 06:38:47Z ckuersteiner $
#
# Filr Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105824");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13825 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-22 07:38:47 +0100 (Fri, 22 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-07-25 16:02:26 +0200 (Mon, 25 Jul 2016)");
  script_name("Filr Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Filr");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("filr/ssh/rls");
  exit(0);
}

include("host_details.inc");

if( ! rls = get_kb_item( "filr/ssh/rls" ) ) exit( 0 );

if( "Filr" >!< rls ) exit( 0 );

set_kb_item( name:"filr/installed", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/a:microfocus:filr';

# product=Novell Filr Appliance
# singleWordProductName=Filr
# version=2.0.0.421
# arch=x86_64
# id=filr-appliance

version = eregmatch( pattern:'version=([0-9]+[^ \r\n]+)', string:rls );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"filr/version", value:vers );
}

register_product( cpe:cpe, location:'ssh',service:'ssh' );

report = build_detection_report( app:"Filr", version:vers, install:"ssh", cpe:cpe, concluded:rls );

log_message( port:0, data:report );

exit( 0 );
