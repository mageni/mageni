###############################################################################
# OpenVAS Vulnerability Test
# $Id: gather-windows-hardware-info.nasl 11287 2018-09-07 10:00:38Z cfischer $
#
# Gather Windows Hardware Information
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107304");
  script_version("$Revision: 11287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 12:00:38 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-04-11 16:48:58 +0200 (Wed, 11 Apr 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Windows Hardware Information");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_wmi_access.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_tag(name:"summary", value:"This script attempts to gather information about the hardware configuration
  from a windows host and stores the results in the KB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

SCRIPT_DESC = "Gather Windows Hardware Information";

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("wmi_os.inc");
include("wmi_file.inc");
include("version_func.inc");

host    = get_host_ip();
usrname = kb_smb_login();
passwd  = kb_smb_password();
if( ! host || ! usrname || ! passwd ) exit( 0 );

domain = kb_smb_domain();
if( domain ) usrname = domain + '\\' + usrname;

handle = wmi_connect( host:host, username:usrname, password:passwd );
if( ! handle ) exit( 0 );

# -- Get the CPU information -- #
# nb: Make sure to update the header variable below if adding new fields here.
# nb: Without DeviceID it is still returned in the query response so explicitly adding it here
# nb: Some WMI implementations (e.g. on Win XP) doesn't provide "NumberOfCores" so checking first if its included in the response.
query1          = "SELECT * FROM Win32_Processor";
processor_infos = wmi_query( wmi_handle:handle, query:query1 );
if( processor_infos && "NumberOfCores" >< processor_infos[0] ) {
  query1 = "SELECT DeviceID, Name, NumberOfCores FROM Win32_Processor";
  header = "DeviceID|Name|NumberOfCores";
  processor_infos = wmi_query( wmi_handle:handle, query:query1 );
} else if( processor_infos ) {
  query1 = "SELECT DeviceID, Name FROM Win32_Processor";
  header = "DeviceID|Name";
  processor_infos = wmi_query( wmi_handle:handle, query:query1 );
}

cpunumber = 0;
cpus      = make_array();

if( processor_infos ) {

  info_list = split( processor_infos, keep:FALSE );

  foreach info( info_list ) {

    # nb: Just ignoring the header
    if( info == header ) continue;

    cpunumber++;

    info_split = split( info, sep:"|", keep:FALSE );

    proc_name = info_split[1];
    num_cores = int( info_split[2] );
    if( ! num_cores ) num_cores = 1;

    if( isnull( cpus[proc_name] ) ) {
      cpus[proc_name] = num_cores;
    } else {
      cpus[proc_name] += num_cores;
    }
  }
}

# -- Get the systems architecture -- #
# nb: Make sure to update the foreach loop below if adding new fields here
# nb: Some WMI implementations doesn't provide the "OSArchitecture" info within
# Win32_OperatingSystem so checking first if its included in the response and
# use a fallback to a possible Arch gathered via SMB.
query2     = "SELECT * FROM Win32_OperatingSystem";
arch_infos = wmi_query( wmi_handle:handle, query:query2 );
arch       = "";
if( arch_infos && "OSArchitecture" >< arch_infos[0] ) {
  query2     = "SELECT OSArchitecture FROM Win32_OperatingSystem";
  arch_infos = wmi_query( wmi_handle:handle, query:query2 );
} else {
  _arch = get_kb_item( "SMB/Windows/Arch" );
  if( _arch && _arch == "x64" ) {
    arch = "64-bit";
  } else if( _arch && _arch == "x86" ) {
    arch = "32-bit";
  } else {
    arch = "unknown";
  }
  arch_infos = "";
  set_kb_item( name:"wmi/login/arch", value:arch );
}

if( arch_infos ) {

  info_list = split( arch_infos, keep:FALSE );

  foreach info( info_list ) {

    # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above
    if( info == "OSArchitecture" ) continue;

    arch = info;
    set_kb_item( name:"wmi/login/arch", value:arch );
  }
}

# -- Get the PCI information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
query3      = "SELECT DeviceID, Manufacturer, Name FROM Win32_PNPEntity WHERE DeviceID LIKE '%PCI\\VEN_%' "; #_156  8086&DEV_156
pci_devices = wmi_query( wmi_handle:handle, query:query3 );

if( pci_devices ) {

  deviceid = 0;
  pci_list = split( pci_devices, keep:FALSE );

  foreach pcidevice( pci_list ) {

    # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above.
    # Sometimes we get something like 2: '' back from the WMI query so also continue in such cases.
    if( pcidevice == "DeviceID|Manufacturer|Name" || pcidevice == "" ) continue;
    deviceid++;
    pcidevice_split = split( pcidevice, sep:"|", keep:FALSE );
    manufacturer    = pcidevice_split[1];
    name            = pcidevice_split[2];

    set_kb_item( name:"ssh_or_wmi/login/pci_devices/available", value:TRUE );
    set_kb_item( name:"wmi/login/pci_devices/available", value:TRUE );
    set_kb_item( name:"wmi/login/pci_devices/device_ids", value:deviceid );

    # nb: Keep "slot, vendor and device" parts of the KB name the same like in the output of lspci -vmm on linux (see gather-hardware-info.nasl)
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/slot", value:deviceid );
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/vendor", value:manufacturer );
    set_kb_item( name:"wmi/login/pci_devices/" + deviceid + "/device", value:name );
  }
}

# -- Get the memory information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
query4  = "SELECT Name, TotalPhysicalMemory FROM Win32_Computersystem";
memory  = wmi_query( wmi_handle:handle, query:query4 );
meminfo = "";

if( memory ) {

  mem_list = split( memory, keep:FALSE );

  foreach mem( mem_list ) {

    # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above
    if( mem == "Name|TotalPhysicalMemory" ) continue;

    mem_split = split( mem, sep:"|", keep:FALSE );
    # nb: We're getting a "data" back here. Using int() to convert it to an integer might cause an integer overflow as we have an uint64 here
    # GOS 5.0 / GVM 10 will fix this so working around this by using a byte for now when getting an negative integer
    memtotal  = mem_split[1];
    _memtotal = int( memtotal );

    if( _memtotal < 0 ) {
      meminfo = memtotal + " B";
    } else if( _memtotal > 0 ) {
      meminfo = ( _memtotal / 1024 ) + " kB";
    } else {
      meminfo = "unknown";
    }
  }
}

# -- Get the network interfaces information -- #
# nb: Make sure to update the foreach loop below if adding new fields here
query5     = "SELECT Description, Index, IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration";
addresses  = wmi_query( wmi_handle:handle, query:query5 );
num_ifaces = 0;
host_ip    = get_host_ip();

if( addresses ) {

  addr_list = split( addresses, keep:FALSE );
  foreach address( addr_list ) {

    # nb: Just ignoring the header, make sure to update this if you add additional fields to the WMI query above
    if( address == "Description|Index|IPAddress|MACAddress" ) continue;

    iface_ipstr = "";
    addr_split  = split( address, sep:"|", keep:FALSE );
    iface_name  = addr_split[0]; # Description

    # IPAddress is coming in with an form like:
    # ifacename1|0|127.0.0.1|127.0.0.2|mac
    # ifacename2|1|127.0.0.3|mac
    # RAS Async Adapter|2|(null)|mac
    # WAN Miniport (IPv6)|5|(null)|(null)
    # so we need to build our IP address here based on the length of the list
    for( i = 2; i < max_index( addr_split ) - 1 ; i ++ ) {
      if( addr_split[i] != "(null)" )
        iface_ipstr += addr_split[i] + ";";
    }
    iface_mac = addr_split[max_index( addr_split ) - 1]; # MACAddress

    # Verification for the MAC address syntax
    iface_mac = eregmatch( pattern:"([0-9a-fA-F:]{17})", string:iface_mac );
    if( ! isnull( iface_mac ) ) {

      num_ifaces++;
      replace_kb_item( name:"wmi/login/net_iface/num_ifaces", value:num_ifaces );

      if( host_ip >< iface_ipstr ) {

        register_host_detail( name:"MAC", value:iface_mac[1], desc:SCRIPT_DESC );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_mac", value:iface_mac[1] );
        if( iface_name != "" ) {
          target_nic = iface_name;
          register_host_detail( name:"NIC", value:iface_name, desc:SCRIPT_DESC );
          set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_name", value:iface_name );
          if( strlen( iface_ipstr ) > 0 ) {
            register_host_detail( name:"NIC_IPS", value:iface_ipstr, desc:SCRIPT_DESC );
            set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_ips", value:iface_ipstr );
          }
        }
      }

      if( iface_name != "" && iface_name != target_nic ) {
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_mac", value:iface_mac[1] );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_name", value:iface_name );
        set_kb_item( name:"wmi/login/net_iface/" + num_ifaces + "/iface_ips", value:iface_ipstr );
        register_host_detail( name:"MAC-Ifaces", value:iface_name + '|' + iface_mac[1] + '|' + iface_ipstr, desc:SCRIPT_DESC );
      }
    } else {
      if( iface_mac != "" && iface_name != "" ) {
        register_host_detail( name:"BROKEN_MAC-Iface", value:iface_name + '|' + iface_mac + '|' + iface_ipstr, desc:SCRIPT_DESC );
      }
    }
  }
}

if( num_ifaces > 0 ) {
  # -- Get the full network interfaces information -- #
  query6       = "SELECT * FROM Win32_NetworkAdapterConfiguration";
  full_netinfo = wmi_query( wmi_handle:handle, query:query6 );
}
netinfo = "";
wmi_close( wmi_handle:handle );

if( full_netinfo ) {
  netinfo = full_netinfo;
}

# -- Store results in the host details DB -- #
if( cpunumber ) {
  cpu_str = "";
  foreach cputype( keys( cpus ) ) {
    if( cpu_str != "" ) {
      cpu_str += '\n';
    }
    cpu_str += string( cpus[cputype], " ", cputype );
  }
  register_host_detail( name:"cpuinfo", value:cpu_str, desc:SCRIPT_DESC );
}

if( arch != "" ) {
  register_host_detail( name:"archinfo", value:arch, desc:SCRIPT_DESC );
}

if( meminfo != "" ) {
  register_host_detail( name:"meminfo", value:meminfo, desc:SCRIPT_DESC );
}

if( netinfo != "" ) {
  register_host_detail( name:"netinfo", value:netinfo, desc:SCRIPT_DESC );
}

exit( 0 );
