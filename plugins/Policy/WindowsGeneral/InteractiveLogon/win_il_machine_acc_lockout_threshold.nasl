##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_il_machine_acc_lockout_threshold.nasl 10661 2018-07-27 13:27:42Z emoss $
#
# Check value for Interactive logon: Machine account lockout threshold
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.312356");
  script_version("$Revision: 10661 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 15:27:42 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-01 15:28:39 +0200 (Fri, 01 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows: Interactive logon: Machine account lockout threshold');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_add_preference(name:"Maximum", type:"entry", value:"10");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy
'Interactive logon: Machine account lockout threshold' on Windows hosts (at
least Windows 8.1).

The setting allows to set a threshold for the number of failed logon attempts
that causes the device to be locked by using BitLocker. This means, if the
specified maximum number of failed logon attempts is exceeded, the device will
invalidate the Trusted Platform Module (TPM) protector and any other protector
except the 48-digit recovery password, and then reboot. During Device Lockout
mode, the computer or device only boots into the touch-enabled Windows Recovery
Environment (WinRE) until an authorized user enters the recovery password to
restore full access.

Failed password attempts on workstations or member servers that have been locked
by using either Ctrl+Alt+Delete or password-protected screen savers count as
failed logon attempts.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

if(get_kb_item("SMB/WindowsVersion") < "6.3"){
  policy_logging(text:'Host is not at least a Microsoft Windows 7 system.
Older versions of Windows are not supported any more. Please update the
Operating System.');
  exit(0);
}

type = 'HKLM';
key = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
item = 'MaxDevicePasswordFailedAttempts';
title = 'Interactive logon: Machine account lockout threshold';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options/' + title;
default = script_get_preference('Maximum');
value = registry_get_dword(key:key, item:item, type:type);
value = chomp(value);

if( value == ''){
  value = '0';
}

if(int(value) == 0 && int(default) == 0){
  compliant = 'yes';
}else if(int(value) <= int(default) && int(value) > 0){
  compliant = 'yes';
}else{
  compliant = 'no';
}

policy_logging(text:'"' + title + '" is set to: ' + value);
policy_add_oid();
policy_set_dval(dval:default);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);
policy_set_kb(val:value);
policy_set_compliance(compliant:compliant);

exit(0);