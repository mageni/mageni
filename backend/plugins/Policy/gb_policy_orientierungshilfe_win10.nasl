##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_orientierungshilfe_win10.nasl 10563 2018-07-22 10:40:42Z cfischer $
#
# AKIF Orientierungshilfe Windows 10: Ueberpruefungen
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
# Emanuel Moss <emanuel.moss@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108078");
  script_version("$Revision: 10563 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-22 12:40:42 +0200 (Sun, 22 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-02-10 10:55:08 +0100 (Fri, 10 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AKIF Orientierungshilfe Windows 10: Ueberpruefungen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsName");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://www.it-sicherheit.mpg.de/Orientierungshilfe_Windows10.pdf");

  script_tag(name:"summary", value:"Diese Routine folgt der 'Orientierungshilfe zur datenarmen
  Konfiguration von Windows 10' des Arbeitskreis Informationssicherheit der deutschen
  Forschungseinrichtungen (AKIF) und ueberprueft das Host-System auf dessen Empfehlungen.");

  script_add_preference(name:"Orientierungshilfe Windows 10 Policies", type:"file", value:"");

  script_tag(name:"qod", value:"98");

  exit(0);
}

include("smb_nt.inc");

if( get_kb_item( "win/lsc/disable_win_cmd_exec" ) ) {
  win_cmd_exec_disabled = TRUE;
}

function check_policy( check_desc, check_num, check_type, reg_key, reg_name, reg_type, reg_value, service_name, startup_type, wmi_username, wmi_password ) {

  local_var check_desc, check_num, check_type, reg_key, reg_name, reg_type, reg_value, service_name;
  local_var startup_type, response, current_value, text_response, serQueryRes, cmd, extra;
  local_var wmi_username, wmi_password;

  if( "Registry" >< check_type ) {

    text_response = check_desc + '||' + check_num + '||' + check_type + '||' + reg_key + '||' + reg_name + '||' + reg_type + '||' + reg_value + '||';

    if( reg_key == "./." ) {
      return make_list( "unimplemented", text_response + 'Ueberpruefungs-Details in Policy Datei fehlen.\n');
    }

    if( "HKCU\" >< reg_key ) {
      reg_key = str_replace( string:reg_key, find:"HKCU\", replace:"", count:1 );
      type = "HKCU";
    } else if( "HKLM\" >< reg_key ) {
      reg_key = str_replace( string:reg_key, find:"HKLM\", replace:"", count:1 );
      type = "HKLM";
    } else {
      return make_list( "error", text_response + '(fehlerhafte "Reg-Key" Details in Policy Datei).\n' );
    }

    if( ! registry_key_exists( key:reg_key, type:type ) ) {
      return make_list( "failed", text_response + 'Registry-Key nicht vorhanden.\n' );
    }

    if( "DWORD" >< reg_type ) {
      current_value = registry_get_dword( key:reg_key, item:reg_name, type:type );
    } else if( "STRING" >< reg_type ) {
      current_value = registry_get_sz( key:reg_key, item:reg_name, type:type );
    } else {
      return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen (fehlerhafte "Reg-Type" Details in Policy Datei).\n' );
    }

    if( isnull( current_value ) ) {
      return make_list( "failed", text_response + 'Registry-Name nicht vorhanden.\n' );
    } else if( current_value == reg_value ) {
      return make_list( "passed", text_response + current_value + '\n' );
    } else if( current_value != reg_value ) {
      return make_list( "failed", text_response + current_value + '\n' );
    } else {
      return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen.\n' );
    }
  } else if( "Service" >< check_type ) {

    text_response = check_desc + '||' + check_num + '||' + check_type + '||' + service_name + '||' + startup_type + '||';

    if( defined_func( "win_cmd_exec" ) ) {

      if( win_cmd_exec_disabled ) {
        return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen. Die Verwendung der benoetigten win_cmd_exec Funktion wurde in "Options for Local Security Checks (OID: 1.3.6.1.4.1.25623.1.0.100509)" manuell deaktiviert.\n' );
      }

      cmd = "cmd /c sc qc " + service_name;
      serQueryRes = win_cmd_exec( cmd:cmd, password:wmi_password, username:wmi_username );

      #START_TYPE         : 2   AUTO_START
      #START_TYPE         : 2   AUTO_START  (DELAYED)
      #START_TYPE         : 3   DEMAND_START
      #START_TYPE         : 4   DISABLED
      if( "START_TYPE" >< serQueryRes ) {
        if( toupper( startup_type ) >< serQueryRes ) {
          return make_list( "passed", text_response + 'Disabled\n' );
        } else if( "AUTO_START" >< serQueryRes && "DELAYED" >< serQueryRes ) {
          return make_list( "failed", text_response + 'Automatic (Delayed Start)\n' );
        } else if( "AUTO_START" >< serQueryRes ) {
          return make_list( "failed", text_response + 'Automatic\n' );
        } else if( "DEMAND_START" >< serQueryRes ) {
          return make_list( "failed", text_response + 'Manual\n' );
        } else {
          if( serQueryRes ) extra = ' Fehlermeldung: ' + chomp( serQueryRes ) + '.';
          return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen.' + extra + '\n' );
        }
      } else if( "Access is denied" >< serQueryRes ) {
        return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen. Der Zugriff wurde verweigert.\n' );
      } else if( "The specified service does not exist as an installed service." >< serQueryRes ) {
        return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen. Der Service existiert nicht.\n' );
      } else {
        if( serQueryRes ) extra = ' Fehlermeldung: ' + chomp( serQueryRes ) + '.';
        return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen.' + extra + '\n' );
      }
    } else {
      return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen (keine WMI Unterstuetzung vorhanden).\n' );
    }
  } else {
    if( reg_key ) {
      text_response = check_desc + '||' + check_num + '||' + check_type + '||' + reg_key + '||' + reg_name + '||' + reg_type + '||' + reg_value + '||';
    } else {
      text_response = check_desc + '||' + check_num + '||' + check_type + '||' + service_name + '||' + startup_type + '||';
    }
    return make_list( "error", text_response + 'Ueberpruefung fehlgeschlagen (fehlerhafte "Ueberpruefung" Details in Policy Datei).\n' );
  }
}

if( ! windows_name = get_kb_item( "SMB/WindowsName" ) ) exit( 0 );

policy_file = script_get_preference_file_content( "Orientierungshilfe Windows 10 Policies" );
if( ! policy_file ) exit( 0 );

policy_lines = split( policy_file, keep:FALSE );

max = max_index( policy_lines );

if( max < 5 ) {
  set_kb_item( name:"policy/orientierungshilfe_win10/error",
               value:"Die Orientierungshilfe Windows 10 Policy Datei ist leer. Es koennen keine Ueberpruefungen durchgefuehrt werden." );
  exit( 0 );
}

if( "Windows 10" >!< windows_name ) {
  set_kb_item( name:"policy/orientierungshilfe_win10/error",
               value:"Es konnte kein Windows 10 erkannt werden (erkanntes OS: " + windows_name + "). Es koennen keine Ueberpruefungen durchgefuehrt werden." );
  exit( 0 );
}

# nb: Windows 10 LTSB (Long Term Servicing Branch) does not have Cortana, Microsoft Edge or Windows Store installed. Thus some registry entries do not have to be set or may vary (IE instead of Edge for example)
if( "LTSB" >< windows_name ) {
  ltsb_version = TRUE;
}

# Login for the win_cmd_exec in check_policy()
wmi_username = kb_smb_login();
wmi_password = kb_smb_password();
wmi_domain = kb_smb_domain();

# We have SMB/WindowsName when reaching this part so a login was possible
# Still exit if something went wrong / is missing
if( ! wmi_username && ! wmi_password ) exit( 0 );
if( wmi_domain ) wmi_username = wmi_domain + "/" + wmi_username;

for( i = 0 ; i < max; i++ ) {

  if( policy_lines[i] == "" ) continue;

  entry = split( policy_lines[i], sep:":", keep:FALSE );
  if( entry[0] == "Beschreibung" ) {
    check_desc = entry[1];
  } else if( entry[0] == "Nummerierung" ) {
    check_num = entry[1];
  } else if( entry[0] == "Ueberpruefung" ) {
    check_type = entry[1];
  } else if( entry[0] == "Reg-Key" ) {
    reg_key = entry[1];
  } else if( entry[0] == "Reg-Name" ) {
    reg_name = entry[1];
  } else if( entry[0] == "Reg-Type" ) {
    reg_type = entry[1];
  } else if( entry[0] == "Reg-Value" ) {
    reg_value = entry[1];
  } else if( entry[0] == "Service-Name" ) {
    service_name = entry[1];
  } else if( entry[0] == "Startup-Type" ) {
    startup_type = entry[1];
  } else if( entry[0] == "Servicing-Branch" ) {
    servicing_branch = entry[1];
  }

  if( ( i == max - 1 ) || ( policy_lines[ i + 1 ] == "" ) ) {
    # there are (at least) two types if servicing branches: LTSB and CB (Current Branch). each registry-entry has a flag LTSB and / or CB
    if( ( ltsb_version && "LTSB" >< servicing_branch ) || ( ! ltsb_version && "CB" >< servicing_branch ) || ( ! servicing_branch ) ) {
      status = check_policy( check_desc:check_desc, check_num:check_num, check_type:check_type, reg_key:reg_key,
                             reg_name:reg_name, reg_type:reg_type, reg_value:reg_value, service_name:service_name,
                             startup_type:startup_type, wmi_username:wmi_username, wmi_password:wmi_password );
      if( status[0] == "passed" ) {
        policy_pass += status[1] + "#-#";
      } else if( status[0] == "failed" ) {
        policy_fail += status[1] + "#-#";
      } else if( status[0] == "unimplemented" ) {
        policy_error += status[1] + "#-#";
      } else if( status[0] == "error" ) {
        policy_error += status[1] + "#-#";
      }
    }

    # Reset previous declared variables in the loop
    check_desc = NULL; check_num = NULL; check_type = NULL; reg_key = NULL; reg_name = NULL; reg_type = NULL; reg_value = NULL; service_name = NULL; startup_type = NULL; servicing_branch = NULL;
  }
}

if( policy_pass )
  set_kb_item( name:"policy/orientierungshilfe_win10/passed", value:policy_pass );
if( policy_fail )
  set_kb_item( name:"policy/orientierungshilfe_win10/failed", value:policy_fail );
if( policy_error )
  set_kb_item( name:"policy/orientierungshilfe_win10/error", value:policy_error );

exit( 0 );
