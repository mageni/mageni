###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_data_domain_detect_ssh.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# EMC Data Domain Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140140");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_name("EMC Data Domain Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of EMC Data Domain.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("emc/data_domain_os/uname");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

if( ! uname = get_kb_item( "emc/data_domain_os/uname" ) ) exit( 0 );

if("Data Domain OS" >!< uname ) exit( 0 );

set_kb_item( name:"emc/data_domain/installed", value:TRUE );

# Welcome to Data Domain OS 6.0.0.9-544198
vb = eregmatch( pattern:'Data Domain OS ([0-9.]+[^-]+)-([0-9]+)', string:uname );

if( ! isnull( vb[1] ) )
  set_kb_item( name:"emc/data_domain/version/ssh", value:vb[1] );

if( ! isnull( vb[2] ) )
  set_kb_item( name:"emc/data_domain/build/ssh", value:vb[2] );

model = ssh_cmd_exec( cmd:"system show modelno" );

if( ! isnull( model ) )
{
  set_kb_item( name:"emc/data_domain/model/ssh", value:model );
  if( "DD VE" >< model )
    set_kb_item( name:"emc/data_domain/is_vm/ssh", value:TRUE );
}

exit( 0 );
