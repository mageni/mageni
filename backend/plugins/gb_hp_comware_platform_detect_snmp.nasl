###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_comware_platform_detect_snmp.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# HP Comware Devices Detect (SNMP)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105797");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-06 11:05:47 +0200 (Wed, 06 Jul 2016)");
  script_name("HP Comware Devices Detect (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of HP Comware Devices");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

# 1.
# HP Comware Platform Software, Software Version 7.1.045, Release 3108P02
# HP 1950-48G-2SFP+-2XGT
# Copyright (c) 2010-2015 Hewlett-Packard Development Company, L.P.
#
# 2.
# HP Series Router MSR931
# HP Comware Platform Software
# Comware Software Version 5.20, Release 2511
# Copyright(c) 2010-2013 Hewlett-Packard Development Company, L.P
#
# 3.
# HP Comware Software. HP 12508 Product Version 12500-CMW710-R7328P01. Copyright (c) 2010-2014 Hewlett-Packard Development Company, L.P.
if( sysdesc !~ 'Comware (Platform )?Software' || ( "Hewlett-Packard Development" >!<  sysdesc && "Hewlett Packard Enterprise Development" >!< sysdesc && "HP Firewall" >!< sysdesc ) ) exit( 0 );

set_kb_item( name:"hp/comware_device", value:TRUE );

cpe = 'cpe:/a:hp:comware';

if( "HP Comware Platform" >< sysdesc && "HP Series Router" >!< sysdesc )
{
  version = eregmatch( pattern:'Software Version ([0-9.]+[^, ]+)', string:sysdesc );

  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    cpe += ':' + vers;
    set_kb_item( name:"hp/comware_device/version", value:vers );
  }

  release = eregmatch( pattern:'Release ([0-9]+[^ ,\r\n]+)', string:sysdesc );
  if( ! isnull( release[1] ) )
  {
    rls = release[1];
    set_kb_item( name:"hp/comware_device/release", value:rls );
  }

  model = eregmatch( pattern:'HP ([^Comware][a-zA-Z0-9]+(-)?[^\r\n]+( EI)?[^ \r\n]+)', string:sysdesc );
  if( ! isnull( model[1] ) )
  {
    mod = model[1];
    set_kb_item( name:"hp/comware_device/model", value:mod );
  }
}
else if( "HP Series Router" >< sysdesc )
{
  version = eregmatch( pattern:'Software Version ([0-9.]+[^, ]+),', string:sysdesc );
  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    cpe += ':' + vers;
    set_kb_item( name:"hp/comware_device/version", value:vers );
  }

  release = eregmatch( pattern:'Release ([0-9]+[^ ,\r\n]+)', string:sysdesc );
  if( ! isnull( release[1] ) )
  {
    rls = release[1];
    set_kb_item( name:"hp/comware_device/release", value:rls );
  }

  model = eregmatch( pattern:'Series Router ([^ \r\n]+)', string:sysdesc );
  if( ! isnull( model[1] ) )
  {
    mod = model[1];
    set_kb_item( name:"hp/comware_device/model", value:mod );
  }
}
else if( sysdesc =~ 'HP Comware Software' )
{
  version = eregmatch( pattern:'Product Version ([^ .\r\n]+-[^ .\r\n]+)', string:sysdesc );

  if( ! isnull( version[1] ) )
  {
    # Model Version Release
    # 12500-CMW710-R7328P01.

    parts = split( version[1], sep:'-', keep:FALSE );
    if( max_index( parts ) == 3 )
    {
      if( ! isnull( parts[1] ) )
      {
        vers = parts[1];
        cpe += ':' + vers;
        set_kb_item( name:"hp/comware_device/version", value:vers );
      }

      if( ! isnull( parts[0] ) )
      {
        mod = parts[0];
        set_kb_item( name:"hp/comware_device/model", value:mod );
      }

      if( ! isnull( parts[2] ) )
      {
         rls = parts[2];
         set_kb_item( name:"hp/comware_device/release", value:rls );
      }

    }
  }

}

register_product( cpe:cpe, location:port + "/udp", proto:"udp", service:"snmp", port:port );
report = 'The remote host is a HP Comware Device\nCPE: ' + cpe + '\n';

if( vers ) report += 'Version:  ' + vers + '\n';
if( rls )  report += 'Release:  ' + rls + '\n';
if( mod )  report += 'Model:    ' + mod + '\n';
           report += 'Concluded from SNMP SysDescription: ' + sysdesc + '\n';

log_message( port:port, data:report, proto:"udp" );

exit( 0 );

