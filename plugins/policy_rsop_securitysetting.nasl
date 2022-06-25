# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150496");
  script_version("2020-12-10T10:38:57+0000");
  script_tag(name:"last_modification", value:"2020-12-10 10:38:57 +0000 (Thu, 10 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-25 07:19:29 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Get RSOP_SecuritySettings");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_login.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/previous-versions/aa375064%28v%3dvs.85%29");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/previous-versions/aa375068(v%3dvs.85)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/previous-versions/aa375062(v%3dvs.85)");

  script_tag(name:"summary", value:"The RSOP_SecuritySettings WMI class is the abstract class from
which other RSoP security classes derive. Instances of this class are not logged. This class was
added for Windows XP.

The RSOP_SecuritySettingNumeric WMI class represents the numeric security setting for an account
policy. Account policies include password policies, account lockout policies, and Kerberos-related
policies.

The RSOP_SecuritySettingString WMI class represents the string security setting for an account policy.

The RSOP_SecuritySettingBoolean WMI class represents the boolean security setting for an account
policy. Account policies include password policies and account lockout policies.

(C) Microsoft Corporation 2015.


Note: This script does not create output, but saves settings for other VTs only.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

rsop_securitysetting_classes = make_list("RSOP_SecuritySettingBoolean", "RSOP_SecuritySettingString", "RSOP_SecuritySettingNumeric");

function wmic_set_kb ( rsop_list, rsop_class ){
  foreach line ( split( rsop_list, keep:FALSE ) ) {
    values = split( line, sep:"|", keep:FALSE );

    keyname = values[0];
    setting = values[2];

    if(keyname =~ "keyname") # skip header
      continue;

    set_kb_item( name:"policy/rsop_securitysetting/" + tolower(rsop_class) + "/" + tolower(keyname), value:setting );
  }
}

function powershell_set_kb( rsop_list, rsop_class ){
  foreach line ( split( rsop_list, keep:FALSE ) ) {
    values = eregmatch( string:line, pattern:"^([a-z,A-Z,0-9]+)\s+([a-z,A-Z,0-9]+)" );

    keyname = values[1];
    setting = values[2];

    set_kb_item( name:"policy/rsop_securitysetting/" + tolower(rsop_class) + "/" + tolower(keyname), value:setting );
  }
}

if( ! infos = kb_smb_wmi_connectinfo() ) {
  set_kb_item(name:"policy/rsop_securitysetting/kb_smb_wmi_connectinfo/error", value:TRUE);
  exit( 0 );
}

if( handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer' ) ) {
  foreach rsop_securitysetting_class ( rsop_securitysetting_classes ) {
    query = "SELECT KeyName, setting FROM " + rsop_securitysetting_class + " WHERE precedence=1";
    ret = wmi_query_rsop( wmi_handle:handle, query:query );
    if ( ! ret || "NTSTATUS" >< ret ) { # NTSTATUS in return on error
      set_kb_item(name:"policy/rsop_securitysetting/" + tolower(rsop_securitysetting_class) + "/error", value:TRUE);
    }else{
      wmic_set_kb ( rsop_list:ret, rsop_class:rsop_securitysetting_class );
    }
  }
}else{
  # if no wmic connection possible, try powershell command (Windows 10 2004 build does not support wmic)
  foreach rsop_securitysetting_class ( rsop_securitysetting_classes ) {
    cmd = "Get-WMIObject " + rsop_securitysetting_class + " -namespace root\rsop\computer -Filter 'precedence=1' | SELECT KeyName, Setting | ft -HideTableHeaders";
    ret = policy_powershell_cmd( cmd:cmd );
    if( ! ret ) {
      set_kb_item(name:"policy/rsop_securitysetting/" + tolower(rsop_securitysetting_class) + "/error", value:TRUE);
    }else{
      powershell_set_kb( rsop_list:ret, rsop_class:rsop_securitysetting_class );
    }
  }
}

exit( 0 );