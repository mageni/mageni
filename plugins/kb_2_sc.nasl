###############################################################################
# OpenVAS Vulnerability Test
# $Id: kb_2_sc.nasl 8033 2017-12-07 15:25:32Z cfischer $
#
# Create System Characteristics
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103998");
  script_version("$Revision: 8033 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 16:25:32 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-03-08 16:17:59 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Create System Characteristics");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl", "os_detection.nasl", "gather-hardware-info.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.mageni.net/docs");

  script_add_preference(name:"Create OVAL System Characteristics", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"Create a System Characteristics element as defined by the OVAL
  specification and store it in the Knowledge Base.

  Note: The created System Characteristics are shown in a separate NVT 'Show System Characteristics' (OID: 1.3.6.1.4.1.25623.1.0.103999).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("plugin_feed_info.inc");
include("host_details.inc");

create_sc = script_get_preference( "Create OVAL System Characteristics" );
if( create_sc == "no" ) exit( 0 );

function fancy_date() {
  local_var datestr;
  datestr =  _FCT_ANON_ARGS[0];
  if( int( datestr ) < 10 ) return string( "0", datestr );
  return datestr;
}

xml = '';
# Please note: If this NVT is extended to produce System Characteristics defined
# in other schemas than the ones listed below it the schemas should be added to
# the xsi:schemaLocation attribute.
xml += string( '<oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" ',
               'xmlns:linux-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux" ',
               'xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" ',
               'xmlns:oval-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" ',
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ',
               'xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5 ',
               'oval-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 ',
               'oval-common-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux linux-system-characteristics-schema.xsd">\n\n' );

l_time = localtime();
month  = fancy_date( l_time["mon"]  );
day    = fancy_date( l_time["mday"] );
hour   = fancy_date( l_time["hour"] );
minute = fancy_date( l_time["min"]  );
sec    = fancy_date( l_time["sec"]  );

xml += string( '\t<generator>\n',
               '\t\t<oval:product_name>', PLUGIN_FEED, '</oval:product_name>\n',
               '\t\t<oval:product_version>', PLUGIN_SET, '</oval:product_version>\n',
               '\t\t<oval:schema_version>5.9</oval:schema_version>\n',
               '\t\t<oval:timestamp>', l_time["year"], '-', month, '-', day, 'T', hour, ':', minute, ':', sec, '</oval:timestamp>\n',
               '\t\t<vendor>', FEED_VENDOR, '</vendor>\n',
               '\t</generator>\n\n' );

xml += string( '\t<system_info>\n' );

os_name = best_os_txt();
if( os_name ) {
  xml += string( '\t\t<os_name>', os_name, '</os_name>\n' );
  os_ver = eregmatch( string:os_name, pattern:"^([a-zA-Z\-\ ]+)([0-9.]+)" );
  if( os_ver[2] ) {
    xml += string( '\t\t<os_version>', os_ver[2], '</os_version>\n' );
  }
} else {
  xml += string( '\t\t<os_name></os_name>\n',
                 '\t\t<os_version></os_version>\n' );
}

arch = get_kb_item( "ssh/login/arch" );
if( arch )
  xml += string( '\t\t<architecture>', arch , '</architecture>\n' );
else
  xml += string( '\t\t<architecture></architecture>\n' );

hostname = get_host_name();
hostip   = get_host_ip();
if( hostname && hostname != hostip )
  xml += string( '\t\t<primary_host_name>', hostname, '</primary_host_name>\n' );
else
  xml += string( '\t\t<primary_host_name></primary_host_name>\n' );

xml += string( '\t\t<interfaces>\n' );

num_ifaces = get_kb_item( "ssh/login/net_iface/num_ifaces" );
if( num_ifaces > 0 ) {
  for( y = 1; y <= num_ifaces; y++ ) {
    xml += string( '\t\t\t<interface>\n' );
    if( iface_name = get_kb_item( "ssh/login/net_iface/" + y + "/iface_name" ) ) {
      xml += string( '\t\t\t\t<interface_name>', iface_name, '</interface_name>\n' );
    } else {
      xml += string( '\t\t\t\t<interface_name></interface_name>\n' );
    }
    if( iface_ips = get_kb_item( "ssh/login/net_iface/" + y + "/iface_ips" ) ) {
      xml += string( '\t\t\t\t<ip_address>', iface_ips, '</ip_address>\n' );
    } else {
      xml += string( '\t\t\t\t<ip_address></ip_address>\n' );
    }
    if( iface_mac = get_kb_item( "ssh/login/net_iface/" + y + "/iface_mac" ) ) {
      xml += string( '\t\t\t\t<mac_address>', iface_mac, '</mac_address>\n' );
    } else {
      xml += string( '\t\t\t\t<mac_address></mac_address>\n' );
    }
    xml += string( '\t\t\t</interface>\n' );
  }
} else {
  xml += string( '\t\t\t<interface>\n',
                 '\t\t\t\t<interface_name></interface_name>\n',
                 '\t\t\t\t<ip_address></ip_address>\n',
                 '\t\t\t\t<mac_address></mac_address>\n',
                 '\t\t\t</interface>\n' );
}

xml += string( '\t\t</interfaces>\n',
               '\t</system_info>\n\n' );

xml += string( '\t<system_data>\n' );
release = get_kb_item( "ssh/login/release" );
if( "RH" >< release ) {
  packages_str = get_kb_item( "ssh/login/rpms" );
  packages_str = str_replace( string:packages_str, find:'\n', replace:'' );
  packages     = split( packages_str, sep:";", keep:FALSE );
  i = 1;
  foreach package( packages ) {
    package_data = split( package, sep:"~", keep:FALSE );
    if( package_data[0] ) {
      xml += string( '\t\t<rpminfo_item id=\"', i, '\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n' );
      xml += string( '\t\t\t<name>', package_data[0], '</name>\n' );
      xml += string( '\t\t\t<arch/>\n' );
      xml += string( '\t\t\t<epoch/>\n' );
      xml += string( '\t\t\t<release>', package_data[1], '</release>\n' );
      xml += string( '\t\t\t<version>', package_data[2], '</version>\n' );
      xml += string( '\t\t\t<evr datatype=\"evr_string\"/>\n' );
      keyid = eregmatch( string:package_data[3], pattern:"Key ID ([0-9a-z]+)" );
      xml += string( '\t\t\t<signature_keyid>', keyid[1], '</signature_keyid>\n' );
      xml += string( '\t\t</rpminfo_item>\n' );
      i++;
    }
  }
}

if( "DEB" >< release ) {
  packages_str = get_kb_item( "ssh/login/packages" );
  packages     = split( packages_str, sep:'\n', keep:FALSE );
  i = 1;
  foreach package( packages ) {
    if( eregmatch( pattern:"^.i[ ]+", string:package ) ) {
      package = ereg_replace( pattern:"([ ]+)", replace:"#", string:package );
      package_data = split( package, sep:"#", keep:FALSE );

      xml += string( '\t\t<dpkginfo_item id=\"', i, '\" xmlns=\"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#linux\">\n' );
      xml += string( '\t\t\t<name>', package_data[1], '</name>\n' );
      xml += string( '\t\t\t<arch/>\n' );
      xml += string( '\t\t\t<epoch/>\n' );
      xml += string( '\t\t\t<release/>\n' );
      xml += string( '\t\t\t<version>', package_data[2], '</version>\n' );
      xml += string( '\t\t\t<evr datatype=\"evr_string\"/>\n' );
      xml += string( '\t\t</dpkginfo_item>\n' );
      i++;
    }
  }
}

xml += string( '\t</system_data>\n' );
xml += string( '</oval_system_characteristics>\n' );

set_kb_item( name:"system_characteristics", value:xml );
set_kb_item( name:"system_characteristics/created", value:TRUE );

exit( 0 );
