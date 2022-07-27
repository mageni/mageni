###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nist_win_oval_sys_char_generator.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# Create System Characteristics for NIST Windows OVAL Definitions
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802042");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-05 12:24:54 +0530 (Thu, 05 Jul 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Create System Characteristics for NIST Windows OVAL Definitions");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_add_preference(name:"Create OVAL System Characteristics for NIST Windows OVAL Definitions", type:"checkbox", value:"no");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://www.mageni.net/docs");

  script_tag(name:"summary", value:"Create a System Characteristics elements as defined by the OVAL specification
  for NIST Windows.xml and store it in the Knowledge Base.

  Note: The created System Characteristics are shown in a separate NVT 'Show System Characteristics' (OID: 1.3.6.1.4.1.25623.1.0.103999).");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("plugin_feed_info.inc");
include("host_details.inc");

SCRIPT_DESC = 'Create System Characteristics for NIST Windows OVAL Definitions';

create_sc = script_get_preference("Create OVAL System Characteristics for NIST Windows OVAL Definitions");
if (create_sc == "no") {
  exit (0);
}

## Global variable
global_var sys_char_id;
sys_char_id = 0;

# start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

function fancy_date() {
  local_var datestr;
  datestr =  _FCT_ANON_ARGS[0];
  if (int (datestr ) < 10) return string ("0", datestr);
  return datestr;
}


## This function return Mac Address and Interface name using WMI function
function get_system_info_using_wmi(host_ip)
{
  sys_info = "";

  usrname = get_kb_item("SMB/login");
  passwd  = get_kb_item("SMB/password");
  domain  = get_kb_item("SMB/domain");
  if( domain ) usrname = domain + '\\' + usrname;

  ## Return empty
  if(!host_ip || !usrname || !passwd){
    return(sys_info);
  }

  ## Execute WMI Query
  handle = wmi_connect(host:host_ip, username:usrname, password:passwd);

  if(!handle){
    return(sys_info);
  }

  ## WMI query to grep the file version
  query = 'SELECT IPAddress, MacAddress, Description FROM Win32_NetworkAdapter' +
          'Configuration Where IPEnabled = True';

  net_adpt_info = wmi_query(wmi_handle:handle, query:query);

  net_adpt_info_list = split(net_adpt_info, sep:'\n', keep:FALSE);

  ## Return list of network interface details
  foreach interface_info (net_adpt_info_list)
  {
    ## Match proper host ip, when multiple ip's are present
    if(host_ip >< interface_info)
    {
      interface_info_list = split(interface_info, sep:'|', keep:FALSE);
      if(max_index(interface_info_list) == 4)
      {
        interface_name = chomp(interface_info_list[0]);
        mac_address = chomp(interface_info_list[3]);

        if(mac_address && mac_address != "")
            register_host_detail(name:"MAC", value:mac_address, desc:SCRIPT_DESC);

      }
      break;
    }
  }

  sys_info = make_list(host_ip, interface_name, mac_address);
  return(sys_info);
}

## This function will create system characteristics for registry item reg_sz and reg_dword
## Default registry hive is HKEY_LOCAL_MACHINE (HKLM)
function create_registry_system_data_char_xml(reg_key, reg_item, reg_type, reg_hive)
{
  local_var status, reg_xml, reg_value, reg_hive, ret_list, key_exists;
  status = "";
  reg_xml = "";
  reg_value = "";

  ## Default Registry hive HKLM
  if(!reg_hive){
    reg_hive = 'HKEY_LOCAL_MACHINE';
  }

  if(reg_type == 'reg_sz'){
    data_type = '';
  } else if(reg_type == 'reg_dword'){
    data_type = ' datatype="int"';
  } else {
    reg_type = '';
    data_type = '';
  }

  ## Increment global sys_char_id
  sys_char_id = sys_char_id + 1;

  ## Exit if some mandatory values are missing
  if(!reg_key || !reg_item || !reg_type){
    ret_list = make_list(reg_xml, reg_value, sys_char_id);
    return(ret_list);
  }

  key_exists = registry_key_exists(key:reg_key);
  ## If Registry Key does not exists
  if(!key_exists){
    status = ' status="does not exist" ';
    reg_xml = '\t\t<registry_item' + status + ' xmlns="http://oval.mitre.org/' +
                 'XMLSchema/oval-system-characteristics-5#windows" id="' +
                 sys_char_id + '">';
    reg_xml += '\t\t\t<hive>' + reg_hive + '</hive>';
    reg_xml += '\t\t\t<key' + status + '>' + reg_key + '</key>';
  }
  else
  {
    if(reg_type == 'reg_sz'){
      reg_value = registry_get_sz(key:reg_key, item:reg_item);
    } else if (reg_type == 'reg_dword') {
      reg_value = registry_get_dword(key:reg_key, item:reg_item);
    }

    ## If Registry Key exists, but reg value does not exist
    if(!reg_value){
      reg_value = "";
      status = ' status="does not exist" ';
    }
    reg_xml = '\t\t<registry_item' + status + ' xmlns="http://oval.mitre.org/' +
                 'XMLSchema/oval-system-characteristics-5#windows" id="'
                 + sys_char_id + '">';
    reg_xml += '\t\t\t<hive>' + reg_hive + '</hive>';
    reg_xml += '\t\t\t<key>' + reg_key + '</key>';

    reg_xml += '\t\t\t<name' + status +'>' + reg_item + '</name>';

    ## If Registry Key and reg value both exists
    if(reg_value){
      reg_xml += '\t\t\t<type>' + reg_type + '</type>';
      reg_xml += '\t\t\t<value' + data_type + '>' + reg_value + '</value>';
    }
  }

  reg_xml += '\t\t</registry_item>';

  ret_list = make_list(reg_xml, reg_value, sys_char_id);

  return(ret_list);
}


## This function will create system characteristics for collected objects
function create_collected_obj_xml(comment, flag, obj_id, version, item_ref, variable_id, variable_value)
{
  local_var coll_obj_xml;
  coll_obj_xml = '';

  if(comment){
    comment = ' comment="' + comment + '" ';
  } else {
    comment = ' ';
  }
  if(flag && obj_id && version && item_ref){
    coll_obj_xml  = '\t\t<object' + comment + 'flag="' + flag + '" id="' + obj_id + '" version="' + version + '">';
    if(variable_id && variable_value){
      coll_obj_xml += '\t\t\t<variable_value variable_id="' + variable_id + '">' + variable_value + '</variable_value>';
    }
    coll_obj_xml += '\t\t\t<reference item_ref="' + item_ref + '"/>';
    coll_obj_xml += '</object>';
  }
  return(coll_obj_xml);

}


## This function will create system characteristics for file item
function create_file_item_sys_data_xml(path, file_name)
{
  local_var status, file_xml, file_ver, c_path, ret_list;
  status = '';
  file_xml = "";
  file_ver = "";

  ## Increment global sys_char_id
  sys_char_id = sys_char_id + 1;

  if(!path || !file_name){
    ret_list = make_list(file_xml, file_ver, sys_char_id);
    return(ret_list);
  }

  file_ver = fetch_file_version(sysPath:path, file_name:file_name);

  if(!file_ver){
    status = ' status="does not exist" ';
  }
  c_path = path  + "\" + file_name;

  file_xml = '\t\t<file_item' + status + ' xmlns="http://oval.mitre.org/XMLSchema/' +
             'oval-system-characteristics-5#windows" id="' + sys_char_id + '">' ;
  file_xml += '\t\t\t<filepath>' + c_path + '</filepath>';
  file_xml += '\t\t\t<path' + status + '>' + path + '</path>';

  if(file_ver)
  {
    file_xml += '\t\t\t<filename>' + file_name + '</filename>';

    #share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
    #file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", c_path);
    #file_size = get_file_size(share:share, file:file);
    #if(file_size){
    #  file_xml += '\t<size datatype="int">' + file_size + '</size>';
    #}

    file_xml += '\t\t\t<version datatype="version">' + file_ver + '</version>';
  }

  file_xml += '\t\t</file_item>';

  ret_list = make_list(file_xml, file_ver, sys_char_id);
  return(ret_list);
}

l_time = "";
sys_data_xml = '';
complete_xml = '';
system_info_xml = '';
collected_obj_xml = '';

complete_xml = string (complete_xml, '<oval_system_characteristics xmlns="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" xmlns:ind-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:oval-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5" xmlns:win-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5 oval-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#windows windows-system-characteristics-schema.xsd http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent independent-system-characteristics-schema.xsd">');

l_time = localtime();

month  = fancy_date ( l_time["mon"]  );
day    = fancy_date ( l_time["mday"] );
hour   = fancy_date ( l_time["hour"] );
minute = fancy_date ( l_time["min"]  );
sec    = fancy_date ( l_time["sec"]  );

complete_xml = string (complete_xml, '\t<generator>\t\t<oval:product_name>', PLUGIN_FEED,
      '</oval:product_name>\t\t<oval:product_version>', PLUGIN_SET,
      '</oval:product_version>\t\t<oval:schema_version>5.10</oval:schema_',
      'version>\t\t<oval:timestamp>', l_time["year"], '-', month, '-', day, 'T',
      hour, ':', minute, ':', sec, '</oval:timestamp>\t\t<vendor>',
      FEED_VENDOR, '</vendor>\t</generator>');

sys_data_xml = string (sys_data_xml, "\t<system_data>");
collected_obj_xml = string (collected_obj_xml, '\t<collected_objects>');

## Generate further details only if it's Windows
if(get_kb_item("SMB/WindowsVersion"))
{
  win_os = get_kb_item("SMB/WindowsName");
  win_sp = get_kb_item("SMB/CSDVersion");
  win_os_ver = get_kb_item("SMB/WindowsVersion");
  win_arch = get_kb_item("SMB/Windows/Arch");
  host_name = get_host_name();

  host_ip = get_host_ip();
  mac_address = "";
  interface_name = "";
  sys_info_list = get_system_info_using_wmi(host_ip:host_ip);
  if(sys_info_list)
  {
    interface_name = sys_info_list[1];
    mac_address = sys_info_list[2];
  }

  win_os_comp_name = win_os + " " + win_sp;

  system_info_xml = string("\t<system_info>\t\t<os_name>", win_os_comp_name, "</os_name>",
                       "\t\t<os_version>", win_os_ver, "</os_version>",
                       "\t\t<architecture>", win_arch, "</architecture>",
                       "\t\t<primary_host_name>", host_name, "</primary_host_name>",
                       "\t\t<interfaces>\t\t\t<interface>",
                       "\t\t\t\t<interface_name>", interface_name,"</interface_name>",
                       "\t\t\t\t<ip_address>", host_ip, "</ip_address>",
                       "\t\t\t\t<mac_address>", mac_address,"</mac_address>",
                       "\t\t\t</interface>\t\t</interfaces>",
                       "</system_info>");

  ## Microsoft exchange
  ms_exchange_key = "SOFTWARE\Microsoft\ExchangeServer\v14\Setup";
  msi_prd_mjr_comment = 'The registry key that holds the MsiProductMajor';
  msi_prd_mjr_flag = 'does not exist';
  msi_prd_mjr_obj_id = 'oval:org.mitre.oval:obj:23591';
  msi_prd_mjr_version = '1';
  msi_prd_mjr_reg_item = 'MsiProductMajor';

  msi_prd_min_comment = 'The registry key that holds the MsiProductMinor';
  msi_prd_min_flag = 'does not exist';
  msi_prd_min_obj_id = 'oval:org.mitre.oval:obj:23564';
  msi_prd_min_version = '1';
  msi_prd_min_reg_item = 'MsiProductMinor';

  msi_build_mjr_comment = 'The registry key that holds the MsiBuildMajor';
  msi_build_mjr_flag = 'does not exist';
  msi_build_mjr_obj_id = 'oval:org.mitre.oval:obj:23905';
  msi_build_mjr_version = '1';
  msi_build_mjr_reg_item = 'MsiBuildMajor';

  msi_build_min_comment = 'The registry key that holds the MsiBuildMinor';
  msi_build_min_flag = 'does not exist';
  msi_build_min_obj_id = 'oval:org.mitre.oval:obj:23987';
  msi_build_min_version = '1';
  msi_build_min_reg_item = 'MsiBuildMinor';

  ms_exchange_keyExists = registry_key_exists(key:ms_exchange_key);
  if(ms_exchange_keyExists){

    ## Product Major Version
    msi_prd_mjr_list = create_registry_system_data_char_xml(reg_key:ms_exchange_key, reg_item:msi_prd_mjr_reg_item, reg_type:"reg_dword");
    msi_prd_mjr_sys_data_xml = msi_prd_mjr_list[0];
    msi_prd_mjr_value = msi_prd_mjr_list[1];
    msi_prd_mjr_item_ref = msi_prd_mjr_list[2];

    if(msi_prd_mjr_sys_data_xml){
      sys_data_xml = string (sys_data_xml, msi_prd_mjr_sys_data_xml);
    }

    if(msi_prd_mjr_value){
      msi_prd_mjr_flag = 'complete';
    }

    msi_prd_mjr_coll_obj_xml = create_collected_obj_xml(comment:msi_prd_mjr_comment, flag:msi_prd_mjr_flag, obj_id:msi_prd_mjr_obj_id, version:msi_prd_mjr_version, item_ref:msi_prd_mjr_item_ref);


    ## Product Minor Version
    msi_prd_min_list = create_registry_system_data_char_xml(reg_key:ms_exchange_key, reg_item:msi_prd_min_reg_item, reg_type:"reg_dword");
    msi_prd_min_sys_data_xml = msi_prd_min_list[0];
    msi_prd_min_value = msi_prd_min_list[1];
    msi_prd_min_item_ref = msi_prd_min_list[2];

    if(msi_prd_min_sys_data_xml){
      sys_data_xml = string (sys_data_xml, msi_prd_min_sys_data_xml);
    }

    if(msi_prd_min_value){
      msi_prd_min_flag = 'complete';
    }
    msi_prd_min_coll_obj_xml = create_collected_obj_xml(comment:msi_prd_min_comment, flag:msi_prd_min_flag, obj_id:msi_prd_min_obj_id, version:msi_prd_min_version, item_ref:msi_prd_min_item_ref);


    msi_build_mjr_list = create_registry_system_data_char_xml(reg_key:ms_exchange_key, reg_item:msi_build_mjr_reg_item, reg_type:"reg_dword");
    msi_build_mjr_sys_data_xml = msi_build_mjr_list[0];
    msi_build_mjr_value = msi_build_mjr_list[1];
    msi_build_mjr_item_ref = msi_build_mjr_list[2];

    if(msi_build_mjr_sys_data_xml){
      sys_data_xml = string (sys_data_xml, msi_build_mjr_sys_data_xml);
    }

    if(msi_build_mjr_value){
      msi_build_mjr_flag = 'complete';
    }
    msi_build_mjr_coll_obj_xml = create_collected_obj_xml(comment:msi_build_mjr_comment, flag:msi_build_mjr_flag, obj_id:msi_build_mjr_obj_id, version:msi_build_mjr_version, item_ref:msi_build_mjr_item_ref);


    msi_build_min_list = create_registry_system_data_char_xml(reg_key:ms_exchange_key, reg_item:msi_build_min_reg_item, reg_type:"reg_dword");
    msi_build_min_sys_data_xml = msi_build_min_list[0];
    msi_build_min_value = msi_build_min_list[1];
    msi_build_min_item_ref = msi_build_min_list[2];

    if(msi_build_min_sys_data_xml){
      sys_data_xml = string (sys_data_xml, msi_build_min_sys_data_xml);
    }

    if(msi_build_min_value){
      msi_build_min_flag = 'complete';
    }
    msi_build_min_coll_obj_xml = create_collected_obj_xml(comment:msi_build_min_comment, flag:msi_build_min_flag, obj_id:msi_build_min_obj_id, version:msi_build_min_version, item_ref:msi_build_min_item_ref);

  } else {
    ## When Microsoft Exchange Server not installed
    sys_char_id = sys_char_id + 1;
    ms_exchange_item_ref = sys_char_id;
    ms_exchange_key_xml = '<registry_item  status="does not exist" xmlns="http:' +
                       '//oval.mitre.org/XMLSchema/oval-system-characteristi' +
                       'cs-5#windows" id="' + ms_exchange_item_ref + '">';
    ms_exchange_key_xml += '\t<hive>HKEY_LOCAL_MACHINE</hive>';
    ms_exchange_key_xml += '\t<key status="does not exist">' + ms_exchange_key + '</key>';
    ms_exchange_key_xml += '\t</registry_item>';

    sys_data_xml = string (sys_data_xml, ms_exchange_key_xml);

    msi_prd_mjr_coll_obj_xml = create_collected_obj_xml(comment:msi_prd_mjr_comment, flag:msi_prd_mjr_flag, obj_id:msi_prd_mjr_obj_id, version:msi_prd_mjr_version, item_ref:ms_exchange_item_ref);

    msi_prd_min_coll_obj_xml = create_collected_obj_xml(comment:msi_prd_min_comment, flag:msi_prd_min_flag, obj_id:msi_prd_min_obj_id, version:msi_prd_min_version, item_ref:ms_exchange_item_ref);

    msi_build_mjr_coll_obj_xml = create_collected_obj_xml(comment:msi_build_mjr_comment, flag:msi_build_mjr_flag, obj_id:msi_build_mjr_obj_id, version:msi_build_mjr_version, item_ref:ms_exchange_item_ref);

    msi_build_min_coll_obj_xml = create_collected_obj_xml(comment:msi_build_min_comment, flag:msi_build_min_flag, obj_id:msi_build_min_obj_id, version:msi_build_min_version, item_ref:ms_exchange_item_ref);
}

  ## Add all microsoft exchange server collected object
  if(msi_prd_mjr_coll_obj_xml){
    collected_obj_xml = string (collected_obj_xml, msi_prd_mjr_coll_obj_xml);
  }

  if(msi_prd_min_coll_obj_xml){
    collected_obj_xml = string (collected_obj_xml, msi_prd_min_coll_obj_xml);
  }

  if(msi_build_mjr_coll_obj_xml){
    collected_obj_xml = string (collected_obj_xml, msi_build_mjr_coll_obj_xml);
  }

  if(msi_build_min_coll_obj_xml){
    collected_obj_xml = string (collected_obj_xml, msi_build_min_coll_obj_xml);
  }


  ## Internet Explorer Ver from Registry
  ie_reg_version_comment = 'This registry key identifies the version of Internet Explorer';
  ie_reg_version_flag = 'does not exist';
  ie_reg_version_id = 'oval:org.mitre.oval:obj:247';
  ie_reg_version_version = '1';
  ie_reg_version_reg_key = "SOFTWARE\Microsoft\Internet Explorer";
  ie_reg_version_reg_item = "Version";

  ie_reg_version_list = create_registry_system_data_char_xml(reg_key:ie_reg_version_reg_key, reg_item:ie_reg_version_reg_item, reg_type:"reg_sz");
  ie_reg_version_sys_data_xml = ie_reg_version_list[0];
  ie_reg_version_value = ie_reg_version_list[1];
  ie_reg_version_item_ref = ie_reg_version_list[2];

  if(ie_reg_version_sys_data_xml){
    sys_data_xml = string (sys_data_xml, ie_reg_version_sys_data_xml);
  }

  if(ie_reg_version_value){
    ie_reg_version_flag = 'complete';
  }

  ie_reg_version_obj_xml = create_collected_obj_xml(comment:ie_reg_version_comment, flag:ie_reg_version_flag, obj_id:ie_reg_version_id, version:ie_reg_version_version, item_ref:ie_reg_version_item_ref);

  if(ie_reg_version_obj_xml){
    collected_obj_xml = string (collected_obj_xml, ie_reg_version_obj_xml);
  }


  ## Processor Arch
  processor_arch_comment = 'This registry key identifies the architecture on the system';
  processor_arch_flag = 'does not exist';
  processor_arch_id = 'oval:org.mitre.oval:obj:1576';
  processor_arch_version = '1';
  processor_arch_reg_key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
  processor_arch_reg_item = "PROCESSOR_ARCHITECTURE";

  processor_arch_list = create_registry_system_data_char_xml(reg_key:processor_arch_reg_key, reg_item:processor_arch_reg_item, reg_type:"reg_sz");
  processor_arch_sys_data_xml = processor_arch_list[0];
  processor_arch_value = processor_arch_list[1];
  processor_arch_item_ref = processor_arch_list[2];

  if(processor_arch_sys_data_xml){
    sys_data_xml = string (sys_data_xml, processor_arch_sys_data_xml);
  }

  if(processor_arch_value){
    processor_arch_flag = 'complete';
  }


  processor_arch_obj_xml = create_collected_obj_xml(comment:processor_arch_comment, flag:processor_arch_flag, obj_id:processor_arch_id, version:processor_arch_version, item_ref:processor_arch_item_ref);

  if(processor_arch_obj_xml){
    collected_obj_xml = string (collected_obj_xml, processor_arch_obj_xml);
  }

  ## CSD Version
  csd_version_comment = 'This registry key holds the service pack installed on the host if one is present.';
  csd_version_flag = 'does not exist';
  csd_version_id = 'oval:org.mitre.oval:obj:717';
  csd_version_version = '3';
  csd_version_reg_key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  csd_version_reg_item = "CSDVersion";

  csd_version_list = create_registry_system_data_char_xml(reg_key:csd_version_reg_key, reg_item:csd_version_reg_item, reg_type:"reg_sz");
  csd_version_sys_data_xml = csd_version_list[0];
  csd_version_value = csd_version_list[1];
  csd_version_item_ref = csd_version_list[2];

  if(csd_version_sys_data_xml){
    sys_data_xml = string (sys_data_xml, csd_version_sys_data_xml);
  }

  if(csd_version_value){
    csd_version_flag = 'complete';
  }

  csd_version_obj_xml = create_collected_obj_xml(comment:csd_version_comment, flag:csd_version_flag, obj_id:csd_version_id, version:csd_version_version, item_ref:csd_version_item_ref);

  if(csd_version_obj_xml){
    collected_obj_xml = string (collected_obj_xml, csd_version_obj_xml);
  }


  ## Product OS Name
  product_os_name_comment = 'This registry key identifies the Windows ProductName';
  product_os_name_flag = 'does not exist';
  product_os_name_id = 'oval:org.mitre.oval:obj:5590';
  product_os_name_version = '1';
  product_os_name_reg_key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  product_os_name_reg_item = "ProductName";

  product_os_name_list = create_registry_system_data_char_xml(reg_key:product_os_name_reg_key, reg_item:product_os_name_reg_item, reg_type:"reg_sz");
  product_os_name_sys_data_xml = product_os_name_list[0];
  product_os_name_value = product_os_name_list[1];
  product_os_name_item_ref = product_os_name_list[2];

  if(product_os_name_sys_data_xml){
    sys_data_xml = string (sys_data_xml, product_os_name_sys_data_xml);
  }

  if(product_os_name_value){
    product_os_name_flag = 'complete';
  }

  product_os_name_obj_xml = create_collected_obj_xml(comment:product_os_name_comment, flag:product_os_name_flag, obj_id:product_os_name_id, version:product_os_name_version, item_ref:product_os_name_item_ref);

  if(product_os_name_obj_xml){
    collected_obj_xml = string (collected_obj_xml, product_os_name_obj_xml);
  }


  ## Common files dir
  common_files_dir_comment = 'The registry key that identifies the location of the common files directory.';
  common_files_dir_flag = 'does not exist';
  common_files_dir_id = 'oval:org.mitre.oval:obj:281';
  common_files_dir_version = '1';
  common_files_dir_reg_key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
  common_files_dir_reg_item = "CommonFilesDir";

  common_files_dir_list = create_registry_system_data_char_xml(reg_key:common_files_dir_reg_key, reg_item:common_files_dir_reg_item, reg_type:"reg_sz");
  common_files_dir_sys_data_xml = common_files_dir_list[0];
  common_files_dir_value = common_files_dir_list[1];
  common_files_dir_item_ref = common_files_dir_list[2];

  if(common_files_dir_sys_data_xml){
    sys_data_xml = string (sys_data_xml, common_files_dir_sys_data_xml);
  }

  if(common_files_dir_value){
    common_files_dir_flag = 'complete';
  }

  common_files_dir_obj_xml = create_collected_obj_xml(comment:common_files_dir_comment, flag:common_files_dir_flag, obj_id:common_files_dir_id, version:common_files_dir_version, item_ref:common_files_dir_item_ref);

  if(common_files_dir_obj_xml){
    collected_obj_xml = string (collected_obj_xml, common_files_dir_obj_xml);
  }


  ## VGX.dll File details
  if(common_files_dir_value)
  {
    vgx_file_flag = 'does not exist';
    vgx_file_id = 'oval:org.mitre.oval:obj:308';
    vgx_file_version = '2';
    vgx_file_variable_id = 'oval:org.mitre.oval:var:209';

    vgx_file_path = common_files_dir_value + "\Microsoft Shared\VGX";
    vgx_file_name = 'vgx.dll';

    vgx_file_list = create_file_item_sys_data_xml(path:vgx_file_path, file_name:vgx_file_name);

    vgx_file_sys_data_xml = vgx_file_list[0];
    vgx_file_value = vgx_file_list[1];
    vgx_file_item_ref = vgx_file_list[2];

    if(vgx_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, vgx_file_sys_data_xml);
    }

    if(vgx_file_value){
      vgx_file_flag = 'complete';
    }

    vgx_file_obj_xml = create_collected_obj_xml(flag:vgx_file_flag, obj_id:vgx_file_id, version:vgx_file_version, item_ref:vgx_file_item_ref, variable_id:vgx_file_variable_id, variable_value:vgx_file_path);

    if(vgx_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, vgx_file_obj_xml);
    }
  }


  ## System Root
  system_root_comment = 'This registry key identifies the system root.';
  system_root_flag = 'does not exist';
  system_root_id = 'oval:org.mitre.oval:obj:219';
  system_root_version = '1';
  system_root_reg_key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  system_root_reg_item = "SystemRoot";

  system_root_list = create_registry_system_data_char_xml(reg_key:system_root_reg_key, reg_item:system_root_reg_item, reg_type:"reg_sz");
  system_root_sys_data_xml = system_root_list[0];
  system_root_value = system_root_list[1];
  system_root_item_ref = system_root_list[2];

  if(system_root_sys_data_xml){
    sys_data_xml = string (sys_data_xml, system_root_sys_data_xml);
  }

  if(system_root_value){
    system_root_flag = 'complete';
  }

  system_root_obj_xml = create_collected_obj_xml(comment:system_root_comment, flag:system_root_flag, obj_id:system_root_id, version:system_root_version, item_ref:system_root_item_ref);

  if(system_root_obj_xml){
    collected_obj_xml = string (collected_obj_xml, system_root_obj_xml);
  }

  if(system_root_value)
  {

    ## win32k.sys file
    win32k_file_flag = 'does not exist';
    win32k_file_id = 'oval:org.mitre.oval:obj:570';
    win32k_file_version = '1';
    win32k_file_variable_id = 'oval:org.mitre.oval:var:200';

    win32k_file_path = system_root_value + "\system32";
    win32k_file_name = 'win32k.sys';

    win32k_file_list = create_file_item_sys_data_xml(path:win32k_file_path, file_name:win32k_file_name);

    win32k_file_sys_data_xml = win32k_file_list[0];
    win32k_file_value = win32k_file_list[1];
    win32k_file_item_ref = win32k_file_list[2];

    if(win32k_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, win32k_file_sys_data_xml);
    }

    if(win32k_file_value){
      win32k_file_flag = 'complete';
    }

    win32k_file_obj_xml = create_collected_obj_xml(flag:win32k_file_flag, obj_id:win32k_file_id, version:win32k_file_version, item_ref:win32k_file_item_ref, variable_id:win32k_file_variable_id, variable_value:win32k_file_path);

    if(win32k_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, win32k_file_obj_xml);
    }


    ## user32.dll file
    user32_file_flag = 'does not exist';
    user32_file_id = 'oval:org.mitre.oval:obj:390';
    user32_file_version = '1';
    user32_file_variable_id = 'oval:org.mitre.oval:var:200';

    user32_file_path = system_root_value + "\system32";
    user32_file_name = 'user32.dll';

    user32_file_list = create_file_item_sys_data_xml(path:user32_file_path, file_name:user32_file_name);

    user32_file_sys_data_xml = user32_file_list[0];
    user32_file_value = user32_file_list[1];
    user32_file_item_ref = user32_file_list[2];

    if(user32_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, user32_file_sys_data_xml);
    }

    if(user32_file_value){
      user32_file_flag = 'complete';
    }

    user32_file_obj_xml = create_collected_obj_xml(flag:user32_file_flag, obj_id:user32_file_id, version:user32_file_version, item_ref:user32_file_item_ref, variable_id:user32_file_variable_id, variable_value:user32_file_path);

    if(user32_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, user32_file_obj_xml);
    }


    ## csrsrc.dll File
    csrsrv_file_flag = 'does not exist';
    csrsrv_file_id = 'oval:org.mitre.oval:obj:2045';
    csrsrv_file_version = '1';
    csrsrv_file_variable_id = 'oval:org.mitre.oval:var:200';

    csrsrv_file_path = system_root_value + "\system32";
    csrsrv_file_name = 'csrsrv.dll';

    csrsrv_file_list = create_file_item_sys_data_xml(path:csrsrv_file_path, file_name:csrsrv_file_name);

    csrsrv_file_sys_data_xml = csrsrv_file_list[0];
    csrsrv_file_value = csrsrv_file_list[1];
    csrsrv_file_item_ref = csrsrv_file_list[2];

    if(csrsrv_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, csrsrv_file_sys_data_xml);
    }

    if(csrsrv_file_value){
      csrsrv_file_flag = 'complete';
    }

    csrsrv_file_obj_xml = create_collected_obj_xml(flag:csrsrv_file_flag, obj_id:csrsrv_file_id, version:csrsrv_file_version, item_ref:csrsrv_file_item_ref, variable_id:csrsrv_file_variable_id, variable_value:csrsrv_file_path);

    if(csrsrv_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, csrsrv_file_obj_xml);
    }

    ## winsrv.dll File
    winsrv_file_flag = 'does not exist';
    winsrv_file_id = 'oval:org.mitre.oval:obj:1382';
    winsrv_file_version = '1';
    winsrv_file_variable_id = 'oval:org.mitre.oval:var:200';

    winsrv_file_path = system_root_value + "\system32";
    winsrv_file_name = 'winsrv.dll';

    winsrv_file_list = create_file_item_sys_data_xml(path:winsrv_file_path, file_name:winsrv_file_name);

    winsrv_file_sys_data_xml = winsrv_file_list[0];
    winsrv_file_value = winsrv_file_list[1];
    winsrv_file_item_ref = winsrv_file_list[2];

    if(winsrv_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, winsrv_file_sys_data_xml);
    }

    if(winsrv_file_value){
      winsrv_file_flag = 'complete';
    }

    winsrv_file_obj_xml = create_collected_obj_xml(flag:winsrv_file_flag, obj_id:winsrv_file_id, version:winsrv_file_version, item_ref:winsrv_file_item_ref, variable_id:winsrv_file_variable_id, variable_value:winsrv_file_path);

    if(winsrv_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, winsrv_file_obj_xml);
    }


    ## mshtml.dll File
    mshtml_file_comment = 'The path to the mshtml.dll file in the system root';
    mshtml_file_flag = 'does not exist';
    mshtml_file_id = 'oval:org.mitre.oval:obj:222';
    mshtml_file_version = '1';
    mshtml_file_variable_id = 'oval:org.mitre.oval:var:200';

    mshtml_file_path = system_root_value + "\system32";
    mshtml_file_name = 'mshtml.dll';

    mshtml_file_list = create_file_item_sys_data_xml(path:mshtml_file_path, file_name:mshtml_file_name);

    mshtml_file_sys_data_xml = mshtml_file_list[0];
    mshtml_file_value = mshtml_file_list[1];
    mshtml_file_item_ref = mshtml_file_list[2];

    if(mshtml_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, mshtml_file_sys_data_xml);
    }

    if(mshtml_file_value){
      mshtml_file_flag = 'complete';
    }

    mshtml_file_obj_xml = create_collected_obj_xml(comment:mshtml_file_comment, flag:mshtml_file_flag, obj_id:mshtml_file_id, version:mshtml_file_version, item_ref:mshtml_file_item_ref, variable_id:mshtml_file_variable_id, variable_value:mshtml_file_path);

    if(mshtml_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, mshtml_file_obj_xml);
    }


    ## iexplore.exe File
    iexplore_file_flag = 'does not exist';
    iexplore_file_id = 'oval:org.mitre.oval:obj:16';
    iexplore_file_version = '1';

    ## This path is hardcoded in windows.xml, hence hard coded here
    iexplore_file_path = "C:\Program Files\Internet Explorer";
    iexplore_file_name = "iexplore.exe";

    iexplore_file_list = create_file_item_sys_data_xml(path:iexplore_file_path, file_name:iexplore_file_name);

    iexplore_file_sys_data_xml = iexplore_file_list[0];
    iexplore_file_value = iexplore_file_list[1];
    iexplore_file_item_ref = iexplore_file_list[2];

    if(iexplore_file_sys_data_xml){
      sys_data_xml = string (sys_data_xml, iexplore_file_sys_data_xml);
    }

    if(iexplore_file_value){
      iexplore_file_flag = 'complete';
    }

    iexplore_file_obj_xml = create_collected_obj_xml(flag:iexplore_file_flag, obj_id:iexplore_file_id, version:iexplore_file_version, item_ref:iexplore_file_item_ref);

    if(iexplore_file_obj_xml){
      collected_obj_xml = string (collected_obj_xml, iexplore_file_obj_xml);
    }
  }

  ## Increment global sys_char_id
  sys_char_id = sys_char_id + 1;

  family_xml = '\t\t<family_item xmlns="http://oval.mitre.org/XMLSchema/oval-sys' +
             'tem-characteristics-5#independent" id="' + sys_char_id + '">' ;
  family_xml = string(family_xml, "\t\t\t<family>windows</family>");
  family_xml = string(family_xml, "\t\t</family_item>");

  sys_data_xml = string (sys_data_xml, family_xml);


  family_comment = 'This is the default family object. Only one family object should exist.';
  family_flag = 'complete';
  family_id = 'oval:org.mitre.oval:obj:99';
  family_version = '1';
  family_item_ref = sys_char_id;

  family_obj_xml = create_collected_obj_xml(comment:family_comment, flag:family_flag, obj_id:family_id, version:family_version, item_ref:family_item_ref);

  if(family_obj_xml){
    collected_obj_xml = string (collected_obj_xml, family_obj_xml);
  }
} else {
  ## Scanned against non windows
  log_message(data:"Test is not applicable for the target system.");
}



sys_data_xml = string (sys_data_xml, "\t</system_data>");
collected_obj_xml = string (collected_obj_xml, "\t</collected_objects>");

if(!system_info_xml)
{
  system_info_xml = string ("\t<system_info>\t\t<os_name></os_name>\t\t<os_version>",
        "</os_version>\t\t<architecture></architecture>\t\t<primary_host_name>",
        "</primary_host_name>\t\t<interfaces>\t\t\t<interface>\t\t\t\t<interfa",
        "ce_name></interface_name>\t\t\t\t<ip_address></ip_address>\t\t\t\t",
        "<mac_address></mac_address>\t\t\t</interface>\t\t</interfaces>\t",
        "</system_info>");
}

complete_xml = string (complete_xml, system_info_xml);
complete_xml = string (complete_xml, collected_obj_xml);
complete_xml = string (complete_xml, sys_data_xml);
complete_xml = string (complete_xml, "</oval_system_characteristics>");

set_kb_item( name:"nist_windows_system_characteristics", value:complete_xml );
set_kb_item( name:"system_characteristics/created", value:TRUE );

exit( 0 );
