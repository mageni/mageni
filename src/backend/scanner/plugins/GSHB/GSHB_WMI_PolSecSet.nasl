###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_WMI_PolSecSet.nasl 10949 2018-08-14 09:36:21Z emoss $
#
# Read all Windows Policy Security Settings (Windows)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96036");
  script_version("$Revision: 10949 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-14 11:36:21 +0200 (Tue, 14 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Read all Windows Policy Security Settings (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"The script read all Windows Policy Security Settings.");

  exit(0);
}
include("wmi_rsop.inc");
include("http_func.inc");
include("smb_nt.inc");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");

if(!OSVER || OSVER >< "none"){
  set_kb_item(name:"WMI/cps/GENERAL", value:"error");
  set_kb_item(name:"WMI/cps/GENERAL/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
  set_kb_item(name:"WMI/Shares", value:"error");
  set_kb_item(name:"WMI/IPC", value:"error");
  set_kb_item(name:"WMI/AUTOSHARE", value:"error");
  set_kb_item(name:"WMI/LMCompatibilityLevel", value:"error");
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"error");
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"error");
  set_kb_item(name:"WMI/LegalNoticeText", value:"error");
  set_kb_item(name:"WMI/RPC-SMBandLDAP", value:"error");
  exit(0);
}

handle = wmi_connect(host:host, username:usrname, password:passwd);

#if(WindowsDomainrole == "4" || WindowsDomainrole == "5")
  handlersop = wmi_connect(host:host, username:usrname, password:passwd, ns:'root\\rsop\\computer');
#else
#  handlersop = wmi_connect_rsop(host:host, username:usrname, password:passwd);

handlereg = wmi_connect_reg(host:host, username:usrname, password:passwd);


if(!handlereg){
  set_kb_item(name:"WMI/cps/GENERAL", value:"error");
  set_kb_item(name:"WMI/cps/GENERAL/log", value:"wmi_connect: WMI Connect failed.");
  set_kb_item(name:"WMI/Shares", value:"error");
  set_kb_item(name:"WMI/IPC", value:"error");
  set_kb_item(name:"WMI/LMCompatibilityLevel", value:"error");
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"error");
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"error");
  set_kb_item(name:"WMI/LegalNoticeText", value:"error");
  set_kb_item(name:"WMI/RPC-SMBandLDAP", value:"error");
  wmi_close(wmi_handle:handle);
  wmi_close(wmi_handle:handlersop);
  wmi_close(wmi_handle:handlereg);
  exit(0);
}

AddPrinterDrivers = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers", val_name:"AddPrinterDrivers");
AllocateCDRoms = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"AllocateCDRoms");
AllocateDASD = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"AllocateDASD");
AllocateFloppies = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"AllocateFloppies");
AuditBaseObjects = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"AuditBaseObjects");
AuthenticodeEnabled = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers", val_name:"AuthenticodeEnabled");
AutoAdminLogon = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"AutoAdminLogon");
autodisconnect = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"autodisconnect");
if (autodisconnect != "0")autodisconnect = hex2dec(xvalue:autodisconnect);
AutoReboot = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\CrashControl", val_name:"AutoReboot");
cachedlogonscount = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"cachedlogonscount");
ClearPageFileAtShutdown = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Session Manager\Memory Management", val_name:"ClearPageFileAtShutdown");
crashonauditfail = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"crashonauditfail");
DisableCAD = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"DisableCAD");
DisableDomainCreds = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"DisableDomainCreds");
disablepasswordchange = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"disablepasswordchange");
DisableIPSourceRouting = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"DisableIPSourceRouting");
DisplayLastLogonInfo = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"DisplayLastLogonInfo");
DisableSavePasswordRasMan = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\RasMan\Parameters", val_name:"DisableSavePassword");
DontDisplayLockedUserId = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"DontDisplayLockedUserId");
EnableDeadGWDetect = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"EnableDeadGWDetect");
enableforcedlogoff = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"enableforcedlogoff");
EnableICMPRedirect = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"EnableICMPRedirect");
EnableSecuritySignatureWs = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", val_name:"EnableSecuritySignature");
EnableSecuritySignatureSvr = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"EnableSecuritySignature");
EveryoneIncludesAnonymous = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"EveryoneIncludesAnonymous");
FIPSAlgorithmPolicy = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"FIPSAlgorithmPolicy");
ForceGuest = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"ForceGuest");
ForceKeyProtection = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Policies\Microsoft\Cryptography", val_name:"ForceKeyProtection");
ForceUnlockLogon = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", val_name:"ForceUnlockLogon");
fullprivilegeauditing = wmi_reg_get_bin_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"fullprivilegeauditing");
Hidden = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Lanmanserver\Parameters", val_name:"Hidden");
KeepAliveTime = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"KeepAliveTime");
if (KeepAliveTime != "0" ) KeepAliveTime = hex2dec(xvalue:KeepAliveTime);
ldapserverintegrity = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\NTDS\Parameters", val_name:"ldapserverintegrity");
LimitBlankPasswordUse = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"LimitBlankPasswordUse");
MachineExactPaths = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths", val_name:"Machine");

MachinePathsKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths");
MachinePathsKEY = tolower(MachinePathsKEY);
if ("machine" >< MachinePathsKEY)
{
MachinePaths = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths", val_name:"Machine");
if (!MachinePaths) MachinePaths = "Empty";
}
else MachinePaths = "None";


MachineAccessRestriction = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\policies\Microsoft\windows NT\DCOM", key_name:"MachineAccessRestriction");
MachineLaunchRestriction = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\policies\Microsoft\windows NT\DCOM", key_name:"MachineLaunchRestriction");
maximumComppasswordage = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"maximumComppasswordage");
if (maximumComppasswordage != "0") maximumComppasswordage = hex2dec(xvalue:maximumComppasswordage);
nodefaultadminowner = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"nodefaultadminowner");
NoDefaultExempt = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\IPSEC", val_name:"NoDefaultExempt");
NoNameReleaseOnDemand = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netbt\Parameters", val_name:"NoNameReleaseOnDemand");
NtfsDisable8dot3NameCreation = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\FileSystem", val_name:"NtfsDisable8dot3NameCreation");


NullSessionPipesKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters");
NullSessionPipesKEY = tolower(NullSessionPipesKEY);
if ("nullsessionpipes" >< NullSessionPipesKEY)
{
NullSessionPipes = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"NullSessionPipes");
if (!NullSessionPipes) NullSessionPipes = "Empty";
}
else NullSessionPipes = "None";

if ("nullsessionshares" >< NullSessionPipesKEY)
{
NullSessionShares = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"NullSessionShares");
if (!NullSessionShares) NullSessionShares = "Empty";
}
else NullSessionShares = "None";


ObCaseInsensitive = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Session Manager\Kernel", val_name:"ObCaseInsensitive");
optional = wmi_reg_get_mul_string_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Session Manager\SubSystems", val_name:"optional");
passwordexpirywarning = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", val_name:"passwordexpirywarning");
if (passwordexpirywarning != "0") passwordexpirywarning = hex2dec(xvalue:passwordexpirywarning);
PerformRouterDiscovery = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"PerformRouterDiscovery");
Policy = wmi_reg_get_bin_val(wmi_handle:handlereg, key:"Software\Microsoft\Driver Signing", val_name:"Policy");
ProtectionMode = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Session Manager", val_name:"ProtectionMode");
RefusePasswordChange = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"RefusePasswordChange");
RestrictAnonymous = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"RestrictAnonymous");
RestrictAnonymousSAM = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"RestrictAnonymousSAM");
restrictnullsessaccess = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"restrictnullsessaccess");
SafeDllSearchMode = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\Session Manager", val_name:"SafeDllSearchMode");
scforceoption = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"scforceoption");
ScreenSaverGracePeriod = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", val_name:"ScreenSaverGracePeriod");
if (ScreenSaverGracePeriod != "0")ScreenSaverGracePeriod = hex2dec(xvalue:ScreenSaverGracePeriod);
scremoveoption = wmi_reg_get_sz(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"scremoveoption");
sealsecurechannel = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"sealsecurechannel");
securitylevel = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole", val_name:"securitylevel");
setcommand = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole", val_name:"setcommand");
ShutdownWithoutLogon = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"ShutdownWithoutLogon");
signsecurechannel = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"signsecurechannel");
SubmitControl = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"SubmitControl");
SynAttackProtect = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"SynAttackProtect");
TcpMaxConnectResponseRetransmissions = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"TcpMaxConnectResponseRetransmissions");
TcpMaxDataRetransmissions = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Tcpip\Parameters", val_name:"TcpMaxDataRetransmissions");
if (TcpMaxDataRetransmissions != "0")TcpMaxDataRetransmissions = hex2dec(xvalue:TcpMaxDataRetransmissions);
undockwithoutlogon = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"Software\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"undockwithoutlogon");
WarningLevel = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\Eventlog\Security", val_name:"WarningLevel");
if (WarningLevel != "0")WarningLevel = hex2dec(xvalue:WarningLevel);
WindowsStore = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"HKLM\Software\Policies\Microsoft\WindowsStore", val_name:"DisableStoreApps");
HandwritingRecognition1 = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization", val_name:"RestrictImplicitTextCollection");
HandwritingRecognition2 = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization", val_name:"RestrictImplicitInkCollection");
DisablePinLogin = wmi_reg_get_dword_val(mi_handle:handlereg, key:"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", val_name:"AllowDomainPINLogon");

val = "None";

if(AddPrinterDrivers == "0" || AddPrinterDrivers){
  set_kb_item(name:"WMI/cps/AddPrinterDrivers", value:AddPrinterDrivers);
}else  set_kb_item(name:"WMI/cps/AddPrinterDrivers", value:val);

if(AllocateCDRoms == "0" || AllocateCDRoms){
  set_kb_item(name:"WMI/cps/AllocateCDRoms", value:AllocateCDRoms);
}else  set_kb_item(name:"WMI/cps/AllocateCDRoms", value:val);

if(AllocateDASD == "0" || AllocateDASD){
  set_kb_item(name:"WMI/cps/AllocateDASD", value:AllocateDASD);
}else  set_kb_item(name:"WMI/cps/AllocateDASD", value:val);

if(AllocateFloppies == "0" || AllocateFloppies){
  set_kb_item(name:"WMI/cps/AllocateFloppies", value:AllocateFloppies);
}else  set_kb_item(name:"WMI/cps/AllocateFloppies", value:val);

if(AuditBaseObjects == "0" || AuditBaseObjects){
  set_kb_item(name:"WMI/cps/AuditBaseObjects", value:AuditBaseObjects);
}else  set_kb_item(name:"WMI/cps/AuditBaseObjects", value:val);

if(AuthenticodeEnabled == "0" || AuthenticodeEnabled){
  set_kb_item(name:"WMI/cps/AuthenticodeEnabled", value:AuthenticodeEnabled);
}else  set_kb_item(name:"WMI/cps/AuthenticodeEnabled", value:val);

if(AutoAdminLogon == "0" || AutoAdminLogon){
  set_kb_item(name:"WMI/cps/AutoAdminLogon", value:AutoAdminLogon);
}else  set_kb_item(name:"WMI/cps/AutoAdminLogon", value:val);

if(autodisconnect == "0" || autodisconnect){
  set_kb_item(name:"WMI/cps/autodisconnect", value:autodisconnect);
}else  set_kb_item(name:"WMI/cps/autodisconnect", value:val);

if(AutoReboot == "0" || AutoReboot){
  set_kb_item(name:"WMI/cps/AutoReboot", value:AutoReboot);
}else  set_kb_item(name:"WMI/cps/AutoReboot", value:val);

if(cachedlogonscount == "0" || cachedlogonscount){
  set_kb_item(name:"WMI/cps/cachedlogonscount", value:cachedlogonscount);
}else  set_kb_item(name:"WMI/cps/cachedlogonscount", value:val);

if(ClearPageFileAtShutdown == "0" || ClearPageFileAtShutdown){
  set_kb_item(name:"WMI/cps/ClearPageFileAtShutdown", value:ClearPageFileAtShutdown);
}else  set_kb_item(name:"WMI/cps/ClearPageFileAtShutdown", value:val);

if(crashonauditfail == "0" || crashonauditfail){
  set_kb_item(name:"WMI/cps/crashonauditfail", value:crashonauditfail);
}else  set_kb_item(name:"WMI/cps/crashonauditfail", value:val);

if(DisableCAD == "0" || DisableCAD){
  set_kb_item(name:"WMI/cps/DisableCAD", value:DisableCAD);
}else  set_kb_item(name:"WMI/cps/DisableCAD", value:val);

if(DisableDomainCreds == "0" || DisableDomainCreds){
  set_kb_item(name:"WMI/cps/DisableDomainCreds", value:DisableDomainCreds);
}else  set_kb_item(name:"WMI/cps/DisableDomainCreds", value:val);


if(DisableIPSourceRouting == "0" || DisableIPSourceRouting){
  set_kb_item(name:"WMI/cps/DisableIPSourceRouting", value:DisableIPSourceRouting);
}else  set_kb_item(name:"WMI/cps/DisableIPSourceRouting", value:val);


if(DisplayLastLogonInfo == "0" || DisplayLastLogonInfo){
  set_kb_item(name:"WMI/cps/DisplayLastLogonInfo", value:DisplayLastLogonInfo);
}else  set_kb_item(name:"WMI/cps/DisplayLastLogonInfo", value:val);

if(disablepasswordchange == "0" || disablepasswordchange){
  set_kb_item(name:"WMI/cps/disablepasswordchange", value:disablepasswordchange);
}else  set_kb_item(name:"WMI/cps/disablepasswordchange", value:val);

if(DisableSavePasswordRasMan == "0" || DisableSavePasswordRasMan){
  set_kb_item(name:"WMI/cps/DisableSavePasswordRasMan", value:DisableSavePasswordRasMan);
}else  set_kb_item(name:"WMI/cps/DisableSavePasswordRasMan", value:val);

if(DontDisplayLockedUserId == "0" || DontDisplayLockedUserId){
  set_kb_item(name:"WMI/cps/DontDisplayLockedUserId", value:DontDisplayLockedUserId);
}else  set_kb_item(name:"WMI/cps/DontDisplayLockedUserId", value:val);

if(EnableDeadGWDetect == "0" || EnableDeadGWDetect){
  set_kb_item(name:"WMI/cps/EnableDeadGWDetect", value:EnableDeadGWDetect);
}else  set_kb_item(name:"WMI/cps/EnableDeadGWDetect", value:val);

if(enableforcedlogoff == "0" || enableforcedlogoff){
  set_kb_item(name:"WMI/cps/enableforcedlogoff", value:enableforcedlogoff);
}else  set_kb_item(name:"WMI/cps/enableforcedlogoff", value:val);

if(EnableICMPRedirect == "0" || EnableICMPRedirect){
  set_kb_item(name:"WMI/cps/EnableICMPRedirect", value:EnableICMPRedirect);
}else  set_kb_item(name:"WMI/cps/EnableICMPRedirect", value:val);

if(EnableSecuritySignatureWs == "0" || EnableSecuritySignatureWs){
  set_kb_item(name:"WMI/cps/EnableSecuritySignatureWs", value:EnableSecuritySignatureWs);
}else  set_kb_item(name:"WMI/cps/EnableSecuritySignatureWs", value:val);

if(EnableSecuritySignatureSvr == "0" || EnableSecuritySignatureSvr){
  set_kb_item(name:"WMI/cps/EnableSecuritySignatureSvr", value:EnableSecuritySignatureSvr);
}else  set_kb_item(name:"WMI/cps/EnableSecuritySignatureSvr", value:val);

if(EveryoneIncludesAnonymous == "0" || EveryoneIncludesAnonymous){
  set_kb_item(name:"WMI/cps/EveryoneIncludesAnonymous", value:EveryoneIncludesAnonymous);
}else  set_kb_item(name:"WMI/cps/EveryoneIncludesAnonymous", value:val);

if(FIPSAlgorithmPolicy == "0" || FIPSAlgorithmPolicy){
  set_kb_item(name:"WMI/cps/FIPSAlgorithmPolicy", value:FIPSAlgorithmPolicy);
}else  set_kb_item(name:"WMI/cps/FIPSAlgorithmPolicy", value:val);

if(ForceGuest == "0" || ForceGuest){
  set_kb_item(name:"WMI/cps/ForceGuest", value:ForceGuest);
}else  set_kb_item(name:"WMI/cps/ForceGuest", value:val);

if(ForceKeyProtection == "0" || ForceKeyProtection){
  set_kb_item(name:"WMI/cps/ForceKeyProtection", value:ForceKeyProtection);
}else  set_kb_item(name:"WMI/cps/ForceKeyProtection", value:val);

if(ForceUnlockLogon == "0" || ForceUnlockLogon){
  set_kb_item(name:"WMI/cps/ForceUnlockLogon", value:ForceUnlockLogon);
}else  set_kb_item(name:"WMI/cps/ForceUnlockLogon", value:val);

if(fullprivilegeauditing == "0" || fullprivilegeauditing){
  set_kb_item(name:"WMI/cps/fullprivilegeauditing", value:fullprivilegeauditing);
}else  set_kb_item(name:"WMI/cps/fullprivilegeauditing", value:val);

if(Hidden == "0" || Hidden){
  set_kb_item(name:"WMI/cps/Hidden", value:Hidden);
}else  set_kb_item(name:"WMI/cps/Hidden", value:val);

if(KeepAliveTime == "0" || KeepAliveTime){
  set_kb_item(name:"WMI/cps/KeepAliveTime", value:KeepAliveTime);
}else  set_kb_item(name:"WMI/cps/KeepAliveTime", value:val);

if(ldapserverintegrity == "0" || ldapserverintegrity){
  set_kb_item(name:"WMI/cps/ldapserverintegrity", value:ldapserverintegrity);
}else  set_kb_item(name:"WMI/cps/ldapserverintegrity", value:val);

if(LimitBlankPasswordUse == "0" || LimitBlankPasswordUse){
  set_kb_item(name:"WMI/cps/LimitBlankPasswordUse", value:LimitBlankPasswordUse);
}else  set_kb_item(name:"WMI/cps/LimitBlankPasswordUse", value:val);

if(MachineExactPaths == "0" || MachineExactPaths){
  set_kb_item(name:"WMI/cps/MachineExactPaths", value:MachineExactPaths);
}else  set_kb_item(name:"WMI/cps/MachineExactPaths", value:val);

if(MachinePaths == "0" || MachinePaths){
  set_kb_item(name:"WMI/cps/MachinePaths", value:MachinePaths);
}else  set_kb_item(name:"WMI/cps/MachinePaths", value:val);

if(MachineAccessRestriction == "0" || MachineAccessRestriction){
  set_kb_item(name:"WMI/cps/MachineAccessRestriction", value:MachineAccessRestriction);
}else  set_kb_item(name:"WMI/cps/MachineAccessRestriction", value:val);

if(MachineLaunchRestriction == "0" || MachineLaunchRestriction){
  set_kb_item(name:"WMI/cps/MachineLaunchRestriction", value:MachineLaunchRestriction);
}else  set_kb_item(name:"WMI/cps/MachineLaunchRestriction", value:val);

if(maximumComppasswordage == "0" || maximumComppasswordage){
  set_kb_item(name:"WMI/cps/maximumComppasswordage", value:maximumComppasswordage);
}else  set_kb_item(name:"WMI/cps/maximumComppasswordage", value:val);

if(nodefaultadminowner == "0" || nodefaultadminowner){
  set_kb_item(name:"WMI/cps/nodefaultadminowner", value:nodefaultadminowner);
}else  set_kb_item(name:"WMI/cps/nodefaultadminowner", value:val);

if(NoDefaultExempt == "0" || NoDefaultExempt){
  set_kb_item(name:"WMI/cps/NoDefaultExempt", value:NoDefaultExempt);
}else  set_kb_item(name:"WMI/cps/NoDefaultExempt", value:val);

if(NoNameReleaseOnDemand == "0" || NoNameReleaseOnDemand){
  set_kb_item(name:"WMI/cps/NoNameReleaseOnDemand", value:NoNameReleaseOnDemand);
}else  set_kb_item(name:"WMI/cps/NoNameReleaseOnDemand", value:val);

if(NtfsDisable8dot3NameCreation == "0" || NtfsDisable8dot3NameCreation){
  set_kb_item(name:"WMI/cps/NtfsDisable8dot3NameCreation", value:NtfsDisable8dot3NameCreation);
}else  set_kb_item(name:"WMI/cps/NtfsDisable8dot3NameCreation", value:val);

if(NullSessionPipes == "0" || NullSessionPipes){
  set_kb_item(name:"WMI/cps/NullSessionPipes", value:NullSessionPipes);
}else  set_kb_item(name:"WMI/cps/NullSessionPipes", value:val);

if(NullSessionShares == "0" || NullSessionShares){
  set_kb_item(name:"WMI/cps/NullSessionShares", value:NullSessionShares);
}else  set_kb_item(name:"WMI/cps/NullSessionShares", value:val);

if(ObCaseInsensitive == "0" || ObCaseInsensitive){
  set_kb_item(name:"WMI/cps/ObCaseInsensitive", value:ObCaseInsensitive);
}else  set_kb_item(name:"WMI/cps/ObCaseInsensitive", value:val);

if(optional == "0" || optional){
  set_kb_item(name:"WMI/cps/optional", value:optional);
}else  set_kb_item(name:"WMI/cps/optional", value:val);

if(passwordexpirywarning == "0" || passwordexpirywarning){
  set_kb_item(name:"WMI/cps/passwordexpirywarning", value:passwordexpirywarning);
}else  set_kb_item(name:"WMI/cps/passwordexpirywarning", value:val);

if(PerformRouterDiscovery == "0" || PerformRouterDiscovery){
  set_kb_item(name:"WMI/cps/PerformRouterDiscovery", value:PerformRouterDiscovery);
}else  set_kb_item(name:"WMI/cps/PerformRouterDiscovery", value:val);

if(Policy == "0" || Policy){
  set_kb_item(name:"WMI/cps/Policy", value:Policy);
}else  set_kb_item(name:"WMI/cps/Policy", value:val);

if(ProtectionMode == "0" || ProtectionMode){
  set_kb_item(name:"WMI/cps/ProtectionMode", value:ProtectionMode);
}else  set_kb_item(name:"WMI/cps/ProtectionMode", value:val);

if(RefusePasswordChange == "0" || RefusePasswordChange){
  set_kb_item(name:"WMI/cps/RefusePasswordChange", value:RefusePasswordChange);
}else  set_kb_item(name:"WMI/cps/RefusePasswordChange", value:val);

if(RestrictAnonymous == "0" || RestrictAnonymous){
  set_kb_item(name:"WMI/cps/RestrictAnonymous", value:RestrictAnonymous);
}else  set_kb_item(name:"WMI/cps/RestrictAnonymous", value:val);

if(RestrictAnonymousSAM == "0" || RestrictAnonymousSAM){
  set_kb_item(name:"WMI/cps/RestrictAnonymousSAM", value:RestrictAnonymousSAM);
}else  set_kb_item(name:"WMI/cps/RestrictAnonymousSAM", value:val);

if(restrictnullsessaccess == "0" || restrictnullsessaccess){
  set_kb_item(name:"WMI/cps/restrictnullsessaccess", value:restrictnullsessaccess);
}else  set_kb_item(name:"WMI/cps/restrictnullsessaccess", value:val);

if (SafeDllSearchMode =="0" || SafeDllSearchMode){
  set_kb_item(name:"WMI/cps/SafeDllSearchMode", value:SafeDllSearchMode);
}else  set_kb_item(name:"WMI/cps/SafeDllSearchMode", value:val);

if(scforceoption == "0" || scforceoption){
  set_kb_item(name:"WMI/cps/scforceoption", value:scforceoption);
}else  set_kb_item(name:"WMI/cps/scforceoption", value:val);

if(ScreenSaverGracePeriod == "0" || ScreenSaverGracePeriod){
  set_kb_item(name:"WMI/cps/ScreenSaverGracePeriod", value:ScreenSaverGracePeriod);
}else  set_kb_item(name:"WMI/cps/ScreenSaverGracePeriod", value:val);

if(scremoveoption == "0" || scremoveoption){
  set_kb_item(name:"WMI/cps/scremoveoption", value:scremoveoption);
}else  set_kb_item(name:"WMI/cps/scremoveoption", value:val);

if(sealsecurechannel == "0" || sealsecurechannel){
  set_kb_item(name:"WMI/cps/sealsecurechannel", value:sealsecurechannel);
}else  set_kb_item(name:"WMI/cps/sealsecurechannel", value:val);

if(securitylevel == "0" || securitylevel){
  set_kb_item(name:"WMI/cps/securitylevel", value:securitylevel);
}else  set_kb_item(name:"WMI/cps/securitylevel", value:val);

if(setcommand == "0" || setcommand){
  set_kb_item(name:"WMI/cps/setcommand", value:setcommand);
}else  set_kb_item(name:"WMI/cps/setcommand", value:val);

if (ShutdownWithoutLogon == "0" || ShutdownWithoutLogon){
  set_kb_item(name:"WMI/cps/ShutdownWithoutLogon", value:ShutdownWithoutLogon);
}else  set_kb_item(name:"WMI/cps/ShutdownWithoutLogon", value:val);

if(signsecurechannel == "0" || signsecurechannel){
  set_kb_item(name:"WMI/cps/signsecurechannel", value:signsecurechannel);
}else  set_kb_item(name:"WMI/cps/signsecurechannel", value:val);

if(SubmitControl == "0" || SubmitControl){
  set_kb_item(name:"WMI/cps/SubmitControl", value:SubmitControl);
}else  set_kb_item(name:"WMI/cps/SubmitControl", value:val);

if(SynAttackProtect == "0" || SynAttackProtect){
  set_kb_item(name:"WMI/cps/SynAttackProtect", value:SynAttackProtect);
}else  set_kb_item(name:"WMI/cps/SynAttackProtect", value:val);

if(TcpMaxConnectResponseRetransmissions == "0" || TcpMaxConnectResponseRetransmissions){
  set_kb_item(name:"WMI/cps/TcpMaxConnectResponseRetransmissions", value:TcpMaxConnectResponseRetransmissions);
}else  set_kb_item(name:"WMI/cps/TcpMaxConnectResponseRetransmissions", value:val);

if(TcpMaxDataRetransmissions == "0" || TcpMaxDataRetransmissions){
  set_kb_item(name:"WMI/cps/TcpMaxDataRetransmissions", value:TcpMaxDataRetransmissions);
}else  set_kb_item(name:"WMI/cps/TcpMaxDataRetransmissions", value:val);

if(undockwithoutlogon == "0" || undockwithoutlogon){
  set_kb_item(name:"WMI/cps/undockwithoutlogon", value:undockwithoutlogon);
}else  set_kb_item(name:"WMI/cps/undockwithoutlogon", value:val);

if(WarningLevel == "0" || WarningLevel){
  set_kb_item(name:"WMI/cps/WarningLevel", value:WarningLevel);
}else  set_kb_item(name:"WMI/cps/WarningLevel", value:val);

if(WindowsStore == "0" || WindowsStore){
  set_kb_item(name:"WMI/Win8Policies/WindowsStore", value:WindowsStore);
}else set_kb_item(name:"WMI/Win8Policies/WindowsStore", value:val);

if(HandwritingRecognition1 == "0" || HandwritingRecognition1){
  set_kb_item(name:"WMI/Win8Policies/HandwritingRecognition1", value:HandwritingRecognition1);
}else set_kb_item(name:"WMI/Win8Policies/HandwritingRecognition1", value:val);

if(HandwritingRecognition2 == "0" || HandwritingRecognition2){
  set_kb_item(name:"WMI/Win8Policies/HandwritingRecognition2", value:HandwritingRecognition2);
}else set_kb_item(name:"WMI/Win8Policies/HandwritingRecognition2", value:val);


#---------------------------------------------------------



AuditAccountLogonQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditAccountLogon' and precedence=1";
AuditAccountManageQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditAccountManage' and precedence=1";
AuditDSAccessQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditDSAccess' and precedence=1";
AuditLogonEventsQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditLogonEvents' and precedence=1";
AuditObjectAccessQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditObjectAccess' and precedence=1";
AuditPolicyChangeQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditPolicyChange' and precedence=1";
AuditPrivilegeUseQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditPrivilegeUse' and precedence=1";
AuditProcessTrackingQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditProcessTracking' and precedence=1";
AuditSystemEventsQuery = "select Failure, Success from RSOP_AuditPolicy where Category='AuditSystemEvents' and precedence=1";
SeNetworkLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeNetworkLogonRight' and precedence=1";
SeTcbPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeTcbPrivilege' and precedence=1";
SeIncreaseQuotaPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeIncreaseQuotaPrivilege' and precedence=1";
SeBackupPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeBackupPrivilege' and precedence=1";
SeChangeNotifyPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeChangeNotifyPrivilege' and precedence=1";
SeSystemtimePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeSystemtimePrivilege' and precedence=1";
SeCreatePagefilePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeCreatePagefilePrivilege' and precedence=1";
SeCreateTokenPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeCreateTokenPrivilege' and precedence=1";
SeCreateGlobalPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeCreateGlobalPrivilege' and precedence=1";
SeCreatePermanentPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeCreatePermanentPrivilege' and precedence=1";
SeDebugPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDebugPrivilege' and precedence=1";
SeDenyNetworkLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyNetworkLogonRight' and precedence=1";
SeEnableDelegationPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeEnableDelegationPrivilege' and precedence=1";
SeRemoteShutdownPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeRemoteShutdownPrivilege' and precedence=1";
SeImpersonatePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeImpersonatePrivilege' and precedence=1";
SeIncreaseBasePriorityPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeIncreaseBasePriorityPrivilege' and precedence=1";
SeLoadDriverPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeLoadDriverPrivilege' and precedence=1";
SeLockMemoryPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeLockMemoryPrivilege' and precedence=1";
SeSecurityPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeSecurityPrivilege' and precedence=1";
SeSystemEnvironmentPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeSystemEnvironmentPrivilege' and precedence=1";
SeManageVolumePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeManageVolumePrivilege' and precedence=1";
SeProfileSingleProcessPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeProfileSingleProcessPrivilege' and precedence=1";
SeSystemProfilePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeSystemProfilePrivilege' and precedence=1";
SeUndockPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeUndockPrivilege' and precedence=1";
SeAssignPrimaryTokenPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeAssignPrimaryTokenPrivilege' and precedence=1";
SeShutdownPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeShutdownPrivilege' and precedence=1";
SeMachineAccountPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeMachineAccountPrivilege' and precedence=1";
SeInteractiveLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeInteractiveLogonRight' and precedence=1";
SeRemoteInteractiveLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeRemoteInteractiveLogonRight' and precedence=1";
SeDenyBatchLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyBatchLogonRight' and precedence=1";
SeDenyServiceLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyServiceLogonRight' and precedence=1";
SeDenyInteractiveLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyInteractiveLogonRight' and precedence=1";
SeDenyRemoteInteractiveLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeDenyRemoteInteractiveLogonRight' and precedence=1";
SeAuditPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeAuditPrivilege' and precedence=1";
SeBatchLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeBatchLogonRight' and precedence=1";
SeServiceLogonRightQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeServiceLogonRight' and precedence=1";
SeRestorePrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeRestorePrivilege' and precedence=1";
SeSyncAgentPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeSyncAgentPrivilege' and precedence=1";
SeTakeOwnershipPrivilegeQuery = "select AccountList from RSOP_UserPrivilegeRight where UserRight='SeTakeOwnershipPrivilege' and precedence=1";
LSAAnonymousNameLookupQuery = "select Setting from RSOP_SecuritySettingBoolean where KeyName='LSAAnonymousNameLookup' and precedence=1";
MaximumLogSizeAppQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='MaximumLogSize' and  precedence=1 and Type='2'";
MaximumLogSizeSecQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='MaximumLogSize' and precedence=1 and Type='1'";
MaximumLogSizeEventQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='MaximumLogSize' and precedence=1 and Type='0'";
RestrictGuestAccessAppQuery = "select Setting from RSOP_SecurityEventLogSettingBoolean where KeyName='RestrictGuestAccess' and precedence=1 and Type='2'";
RestrictGuestAccessSecQuery = "select Setting from RSOP_SecurityEventLogSettingBoolean where KeyName='RestrictGuestAccess' and precedence=1 and Type='1'";
RestrictGuestAccessEventQuery = "select Setting from RSOP_SecurityEventLogSettingBoolean where KeyName='RestrictGuestAccess' and precedence=1 and Type='0'";
RetentionDaysAppQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='RetentionDays' and precedence=1 and Type='2'";
RetentionDaysSecQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='RetentionDays' and precedence=1 and Type='1'";
RetentionDaysEventQuery = "select Setting from RSOP_SecurityEventLogSettingNumeric where KeyName='RetentionDays' and precedence=1 and Type='0'";
TicketValidateClientQuery = "select Setting from RSOP_SecuritySettingBoolean where KeyName='TicketValidateClient' and precedence=1";

MaxClockSkewQuery = "select Setting from RSOP_SecuritySettingNumeric where KeyName='MaxClockSkew' and precedence=1";
MaxServiceAgeQuery = "select Setting from RSOP_SecuritySettingNumeric where KeyName='MaxServiceAge' and precedence=1";
MaxRenewAgeQuery = "select Setting from RSOP_SecuritySettingNumeric where KeyName='MaxRenewAge' and precedence=1";
MaxTicketAgeQuery = "select Setting from RSOP_SecuritySettingNumeric where KeyName='MaxTicketAge' and precedence=1";

OverWritePolicyAppQuery = "select OverWritePolicy from Win32_NTEventlogFile where FileName='Application' Or FileName='AppEvent'";
OverWritePolicySecQuery = "select OverWritePolicy from Win32_NTEventlogFile where FileName='Security' Or FileName='SecEvent'";
OverWritePolicyEventQuery = "select OverWritePolicy from Win32_NTEventlogFile where FileName='System' Or FileName='SysEvent'";


AuditAccountLogon = wmi_query_rsop(wmi_handle:handlersop, query:AuditAccountLogonQuery);
AuditAccountManage = wmi_query_rsop(wmi_handle:handlersop, query:AuditAccountManageQuery);
AuditDSAccess = wmi_query_rsop(wmi_handle:handlersop, query:AuditDSAccessQuery);
AuditLogonEvents = wmi_query_rsop(wmi_handle:handlersop, query:AuditLogonEventsQuery);
AuditObjectAccess = wmi_query_rsop(wmi_handle:handlersop, query:AuditObjectAccessQuery);
AuditPolicyChange = wmi_query_rsop(wmi_handle:handlersop, query:AuditPolicyChangeQuery);
AuditPrivilegeUse = wmi_query_rsop(wmi_handle:handlersop, query:AuditPrivilegeUseQuery);
AuditProcessTracking = wmi_query_rsop(wmi_handle:handlersop, query:AuditProcessTrackingQuery);
AuditSystemEvents = wmi_query_rsop(wmi_handle:handlersop, query:AuditSystemEventsQuery);
SeNetworkLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeNetworkLogonRightQuery);
SeTcbPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeTcbPrivilegeQuery);
SeIncreaseQuotaPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeIncreaseQuotaPrivilegeQuery);
SeBackupPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeBackupPrivilegeQuery);
SeChangeNotifyPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeChangeNotifyPrivilegeQuery);
SeSystemtimePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeSystemtimePrivilegeQuery);
SeCreatePagefilePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeCreatePagefilePrivilegeQuery);
SeCreateTokenPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeCreateTokenPrivilegeQuery);
SeCreateGlobalPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeCreateGlobalPrivilegeQuery);
SeCreatePermanentPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeCreatePermanentPrivilegeQuery);
SeDebugPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeDebugPrivilegeQuery);
SeDenyNetworkLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeDenyNetworkLogonRightQuery);
SeEnableDelegationPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeEnableDelegationPrivilegeQuery);
SeRemoteShutdownPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeRemoteShutdownPrivilegeQuery);
SeImpersonatePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeImpersonatePrivilegeQuery);
SeIncreaseBasePriorityPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeIncreaseBasePriorityPrivilegeQuery);
SeLoadDriverPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeLoadDriverPrivilegeQuery);
SeLockMemoryPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeLockMemoryPrivilegeQuery);
SeSecurityPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeSecurityPrivilegeQuery);
SeSystemEnvironmentPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeSystemEnvironmentPrivilegeQuery);
SeManageVolumePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeManageVolumePrivilegeQuery);
SeProfileSingleProcessPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeProfileSingleProcessPrivilegeQuery);
SeSystemProfilePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeSystemProfilePrivilegeQuery);
SeUndockPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeUndockPrivilegeQuery);
SeAssignPrimaryTokenPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeAssignPrimaryTokenPrivilegeQuery);
SeShutdownPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeShutdownPrivilegeQuery);
SeMachineAccountPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeMachineAccountPrivilegeQuery);
SeInteractiveLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeInteractiveLogonRightQuery);
SeRemoteInteractiveLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeRemoteInteractiveLogonRightQuery);
SeDenyBatchLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeDenyBatchLogonRightQuery);
SeDenyServiceLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeDenyServiceLogonRightQuery);
SeDenyInteractiveLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeDenyInteractiveLogonRightQuery);
SeDenyRemoteInteractiveLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeDenyRemoteInteractiveLogonRightQuery);
SeAuditPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeAuditPrivilegeQuery);
SeBatchLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeBatchLogonRightQuery);
SeServiceLogonRight = wmi_query_rsop(wmi_handle:handlersop, query:SeServiceLogonRightQuery);
SeRestorePrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeRestorePrivilegeQuery);
SeSyncAgentPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeSyncAgentPrivilegeQuery);
SeTakeOwnershipPrivilege = wmi_query_rsop(wmi_handle:handlersop, query:SeTakeOwnershipPrivilegeQuery);
LSAAnonymousNameLookup = wmi_query_rsop(wmi_handle:handlersop, query:LSAAnonymousNameLookupQuery);
MaximumLogSizeApp = wmi_query_rsop(wmi_handle:handlersop, query:MaximumLogSizeAppQuery);
MaximumLogSizeSec = wmi_query_rsop(wmi_handle:handlersop, query:MaximumLogSizeSecQuery);
MaximumLogSizeEvent = wmi_query_rsop(wmi_handle:handlersop, query:MaximumLogSizeEventQuery);
RestrictGuestAccessApp = wmi_query_rsop(wmi_handle:handlersop, query:RestrictGuestAccessAppQuery);
RestrictGuestAccessSec = wmi_query_rsop(wmi_handle:handlersop, query:RestrictGuestAccessSecQuery);
RestrictGuestAccessEvent = wmi_query_rsop(wmi_handle:handlersop, query:RestrictGuestAccessEventQuery);
RetentionDaysApp = wmi_query_rsop(wmi_handle:handlersop, query:RetentionDaysAppQuery);
RetentionDaysSec = wmi_query_rsop(wmi_handle:handlersop, query:RetentionDaysSecQuery);
RetentionDaysEvent = wmi_query_rsop(wmi_handle:handlersop, query:RetentionDaysEventQuery);
TicketValidateClient = wmi_query_rsop(wmi_handle:handlersop, query:TicketValidateClientQuery);
MaxClockSkew = wmi_query_rsop(wmi_handle:handlersop, query:MaxClockSkewQuery);
MaxServiceAge = wmi_query_rsop(wmi_handle:handlersop, query:MaxServiceAgeQuery);
MaxRenewAge = wmi_query_rsop(wmi_handle:handlersop, query:MaxRenewAgeQuery);
MaxTicketAge = wmi_query_rsop(wmi_handle:handlersop, query:MaxTicketAgeQuery);
OverWritePolicyApp = wmi_query(wmi_handle:handle, query:OverWritePolicyAppQuery);
OverWritePolicySec = wmi_query(wmi_handle:handle, query:OverWritePolicySecQuery);
OverWritePolicyEvent = wmi_query(wmi_handle:handle, query:OverWritePolicyEventQuery);

if(AuditAccountLogon || AuditAccountLogon == "0"){
  set_kb_item(name:"WMI/cps/AuditAccountLogon", value:AuditAccountLogon);
}else  set_kb_item(name:"WMI/cps/AuditAccountLogon", value:val);

if(AuditAccountManage || AuditAccountManage == "0"){
  set_kb_item(name:"WMI/cps/AuditAccountManage", value:AuditAccountManage);
}else  set_kb_item(name:"WMI/cps/AuditAccountManage", value:val);

if(AuditDSAccess || AuditDSAccess == "0"){
  set_kb_item(name:"WMI/cps/AuditDSAccess", value:AuditDSAccess);
}else  set_kb_item(name:"WMI/cps/AuditDSAccess", value:val);

if(AuditLogonEvents || AuditLogonEvents == "0"){
  set_kb_item(name:"WMI/cps/AuditLogonEvents", value:AuditLogonEvents);
}else  set_kb_item(name:"WMI/cps/AuditLogonEvents", value:val);

if(AuditObjectAccess || AuditObjectAccess == "0"){
  set_kb_item(name:"WMI/cps/AuditObjectAccess", value:AuditObjectAccess);
}else  set_kb_item(name:"WMI/cps/AuditObjectAccess", value:val);

if(AuditPolicyChange || AuditPolicyChange == "0"){
  set_kb_item(name:"WMI/cps/AuditPolicyChange", value:AuditPolicyChange);
}else  set_kb_item(name:"WMI/cps/AuditPolicyChange", value:val);

if(AuditPrivilegeUse || AuditPrivilegeUse == "0"){
  set_kb_item(name:"WMI/cps/AuditPrivilegeUse", value:AuditPrivilegeUse);
}else  set_kb_item(name:"WMI/cps/AuditPrivilegeUse", value:val);

if(AuditProcessTracking || AuditProcessTracking == "0"){
  set_kb_item(name:"WMI/cps/AuditProcessTracking", value:AuditProcessTracking);
}else  set_kb_item(name:"WMI/cps/AuditProcessTracking", value:val);

if(AuditSystemEvents || AuditSystemEvents == "0"){
  set_kb_item(name:"WMI/cps/AuditSystemEvents", value:AuditSystemEvents);
}else  set_kb_item(name:"WMI/cps/AuditSystemEvents", value:val);

if(SeNetworkLogonRight || SeNetworkLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeNetworkLogonRight", value:SeNetworkLogonRight);
}else  set_kb_item(name:"WMI/cps/SeNetworkLogonRight", value:val);

if(SeTcbPrivilege || SeTcbPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeTcbPrivilege", value:SeTcbPrivilege);
}else  set_kb_item(name:"WMI/cps/SeTcbPrivilege", value:val);

if(SeIncreaseQuotaPrivilege || SeIncreaseQuotaPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeIncreaseQuotaPrivilege", value:SeIncreaseQuotaPrivilege);
}else  set_kb_item(name:"WMI/cps/SeIncreaseQuotaPrivilege", value:val);

if(SeBackupPrivilege || SeBackupPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeBackupPrivilege", value:SeBackupPrivilege);
}else  set_kb_item(name:"WMI/cps/SeBackupPrivilege", value:val);

if(SeChangeNotifyPrivilege || SeChangeNotifyPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeChangeNotifyPrivilege", value:SeChangeNotifyPrivilege);
}else  set_kb_item(name:"WMI/cps/SeChangeNotifyPrivilege", value:val);

if(SeSystemtimePrivilege || SeSystemtimePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeSystemtimePrivilege", value:SeSystemtimePrivilege);
}else  set_kb_item(name:"WMI/cps/SeSystemtimePrivilege", value:val);

if(SeCreatePagefilePrivilege || SeCreatePagefilePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeCreatePagefilePrivilege", value:SeCreatePagefilePrivilege);
}else  set_kb_item(name:"WMI/cps/SeCreatePagefilePrivilege", value:val);

if(SeCreateTokenPrivilege || SeCreateTokenPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeCreateTokenPrivilege", value:SeCreateTokenPrivilege);
}else  set_kb_item(name:"WMI/cps/SeCreateTokenPrivilege", value:val);

if(SeCreateGlobalPrivilege || SeCreateGlobalPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeCreateGlobalPrivilege", value:SeCreateGlobalPrivilege);
}else  set_kb_item(name:"WMI/cps/SeCreateGlobalPrivilege", value:val);

if(SeCreatePermanentPrivilege || SeCreatePermanentPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeCreatePermanentPrivilege", value:SeCreatePermanentPrivilege);
}else  set_kb_item(name:"WMI/cps/SeCreatePermanentPrivilege", value:val);

if(SeDebugPrivilege || SeDebugPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeDebugPrivilege", value:SeDebugPrivilege);
}else  set_kb_item(name:"WMI/cps/SeDebugPrivilege", value:val);

if(SeDenyNetworkLogonRight || SeDenyNetworkLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeDenyNetworkLogonRight", value:SeDenyNetworkLogonRight);
}else  set_kb_item(name:"WMI/cps/SeDenyNetworkLogonRight", value:val);

if(SeEnableDelegationPrivilege || SeEnableDelegationPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeEnableDelegationPrivilege", value:SeEnableDelegationPrivilege);
}else  set_kb_item(name:"WMI/cps/SeEnableDelegationPrivilege", value:val);

if(SeRemoteShutdownPrivilege || SeRemoteShutdownPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeRemoteShutdownPrivilege", value:SeRemoteShutdownPrivilege);
}else  set_kb_item(name:"WMI/cps/SeRemoteShutdownPrivilege", value:val);

if(SeImpersonatePrivilege || SeImpersonatePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeImpersonatePrivilege", value:SeImpersonatePrivilege);
}else  set_kb_item(name:"WMI/cps/SeImpersonatePrivilege", value:val);

if(SeIncreaseBasePriorityPrivilege || SeIncreaseBasePriorityPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeIncreaseBasePriorityPrivilege", value:SeIncreaseBasePriorityPrivilege);
}else  set_kb_item(name:"WMI/cps/SeIncreaseBasePriorityPrivilege", value:val);

if(SeLoadDriverPrivilege || SeLoadDriverPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeLoadDriverPrivilege", value:SeLoadDriverPrivilege);
}else  set_kb_item(name:"WMI/cps/SeLoadDriverPrivilege", value:val);

if(SeLockMemoryPrivilege || SeLockMemoryPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeLockMemoryPrivilege", value:SeLockMemoryPrivilege);
}else  set_kb_item(name:"WMI/cps/SeLockMemoryPrivilege", value:val);

if(SeSecurityPrivilege || SeSecurityPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeSecurityPrivilege", value:SeSecurityPrivilege);
}else  set_kb_item(name:"WMI/cps/SeSecurityPrivilege", value:val);

if(SeSystemEnvironmentPrivilege || SeSystemEnvironmentPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeSystemEnvironmentPrivilege", value:SeSystemEnvironmentPrivilege);
}else  set_kb_item(name:"WMI/cps/SeSystemEnvironmentPrivilege", value:val);

if(SeManageVolumePrivilege || SeManageVolumePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeManageVolumePrivilege", value:SeManageVolumePrivilege);
}else  set_kb_item(name:"WMI/cps/SeManageVolumePrivilege", value:val);

if(SeProfileSingleProcessPrivilege || SeProfileSingleProcessPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeProfileSingleProcessPrivilege", value:SeProfileSingleProcessPrivilege);
}else  set_kb_item(name:"WMI/cps/SeProfileSingleProcessPrivilege", value:val);

if(SeSystemProfilePrivilege || SeSystemProfilePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeSystemProfilePrivilege", value:SeSystemProfilePrivilege);
}else  set_kb_item(name:"WMI/cps/SeSystemProfilePrivilege", value:val);

if(SeUndockPrivilege || SeUndockPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeUndockPrivilege", value:SeUndockPrivilege);
}else  set_kb_item(name:"WMI/cps/SeUndockPrivilege", value:val);

if(SeAssignPrimaryTokenPrivilege || SeAssignPrimaryTokenPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeAssignPrimaryTokenPrivilege", value:SeAssignPrimaryTokenPrivilege);
}else  set_kb_item(name:"WMI/cps/SeAssignPrimaryTokenPrivilege", value:val);

if(SeShutdownPrivilege || SeShutdownPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeShutdownPrivilege", value:SeShutdownPrivilege);
}else  set_kb_item(name:"WMI/cps/SeShutdownPrivilege", value:val);

if(SeMachineAccountPrivilege || SeMachineAccountPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeMachineAccountPrivilege", value:SeMachineAccountPrivilege);
}else  set_kb_item(name:"WMI/cps/SeMachineAccountPrivilege", value:val);

if(SeInteractiveLogonRight || SeInteractiveLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeInteractiveLogonRight", value:SeInteractiveLogonRight);
}else  set_kb_item(name:"WMI/cps/SeInteractiveLogonRight", value:val);

if(SeRemoteInteractiveLogonRight || SeRemoteInteractiveLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeRemoteInteractiveLogonRight", value:SeRemoteInteractiveLogonRight);
}else  set_kb_item(name:"WMI/cps/SeRemoteInteractiveLogonRight", value:val);

if(SeDenyBatchLogonRight || SeDenyBatchLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeDenyBatchLogonRight", value:SeDenyBatchLogonRight);
}else  set_kb_item(name:"WMI/cps/SeDenyBatchLogonRight", value:val);

if(SeDenyServiceLogonRight || SeDenyServiceLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeDenyServiceLogonRight", value:SeDenyServiceLogonRight);
}else  set_kb_item(name:"WMI/cps/SeDenyServiceLogonRight", value:val);

if(SeDenyInteractiveLogonRight || SeDenyInteractiveLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeDenyInteractiveLogonRight", value:SeDenyInteractiveLogonRight);
}else  set_kb_item(name:"WMI/cps/SeDenyInteractiveLogonRight", value:val);

if(SeDenyRemoteInteractiveLogonRight || SeDenyRemoteInteractiveLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeDenyRemoteInteractiveLogonRight", value:SeDenyRemoteInteractiveLogonRight);
}else  set_kb_item(name:"WMI/cps/SeDenyRemoteInteractiveLogonRight", value:val);

if(SeAuditPrivilege || SeAuditPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeAuditPrivilege", value:SeAuditPrivilege);
}else  set_kb_item(name:"WMI/cps/SeAuditPrivilege", value:val);

if(SeBatchLogonRight || SeBatchLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeBatchLogonRight", value:SeBatchLogonRight);
}else  set_kb_item(name:"WMI/cps/SeBatchLogonRight", value:val);

if(SeServiceLogonRight || SeServiceLogonRight == "0"){
  set_kb_item(name:"WMI/cps/SeServiceLogonRight", value:SeServiceLogonRight);
}else  set_kb_item(name:"WMI/cps/SeServiceLogonRight", value:val);

if(SeRestorePrivilege || SeRestorePrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeRestorePrivilege", value:SeRestorePrivilege);
}else  set_kb_item(name:"WMI/cps/SeRestorePrivilege", value:val);

if(SeSyncAgentPrivilege || SeSyncAgentPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeSyncAgentPrivilege", value:SeSyncAgentPrivilege);
}else  set_kb_item(name:"WMI/cps/SeSyncAgentPrivilege", value:val);

if(SeTakeOwnershipPrivilege || SeTakeOwnershipPrivilege == "0"){
  set_kb_item(name:"WMI/cps/SeTakeOwnershipPrivilege", value:SeTakeOwnershipPrivilege);
}else  set_kb_item(name:"WMI/cps/SeTakeOwnershipPrivilege", value:val);

if(LSAAnonymousNameLookup || LSAAnonymousNameLookup == "0"){
  set_kb_item(name:"WMI/cps/LSAAnonymousNameLookup", value:LSAAnonymousNameLookup);
}else  set_kb_item(name:"WMI/cps/LSAAnonymousNameLookup", value:val);

if(MaximumLogSizeApp || MaximumLogSizeApp == "0"){
  set_kb_item(name:"WMI/cps/MaximumLogSizeApp", value:MaximumLogSizeApp);
}else  set_kb_item(name:"WMI/cps/MaximumLogSizeApp", value:val);

if(MaximumLogSizeSec || MaximumLogSizeSec == "0"){
  set_kb_item(name:"WMI/cps/MaximumLogSizeSec", value:MaximumLogSizeSec);
}else  set_kb_item(name:"WMI/cps/MaximumLogSizeSec", value:val);

if(MaximumLogSizeEvent || MaximumLogSizeEvent == "0"){
  set_kb_item(name:"WMI/cps/MaximumLogSizeEvent", value:MaximumLogSizeEvent);
}else  set_kb_item(name:"WMI/cps/MaximumLogSizeEvent", value:val);

if(RestrictGuestAccessApp || RestrictGuestAccessApp == "0"){
  set_kb_item(name:"WMI/cps/RestrictGuestAccessApp", value:RestrictGuestAccessApp);
}else  set_kb_item(name:"WMI/cps/RestrictGuestAccessApp", value:val);

if(RestrictGuestAccessSec || RestrictGuestAccessSec == "0"){
  set_kb_item(name:"WMI/cps/RestrictGuestAccessSec", value:RestrictGuestAccessSec);
}else  set_kb_item(name:"WMI/cps/RestrictGuestAccessSec", value:val);

if(RestrictGuestAccessEvent || RestrictGuestAccessEvent == "0"){
  set_kb_item(name:"WMI/cps/RestrictGuestAccessEvent", value:RestrictGuestAccessEvent);
}else  set_kb_item(name:"WMI/cps/RestrictGuestAccessEvent", value:val);

if(RetentionDaysApp || RetentionDaysApp == "0"){
  set_kb_item(name:"WMI/cps/RetentionDaysApp", value:RetentionDaysApp);
}else  set_kb_item(name:"WMI/cps/RetentionDaysApp", value:val);

if(RetentionDaysSec || RetentionDaysSec == "0"){
  set_kb_item(name:"WMI/cps/RetentionDaysSec", value:RetentionDaysSec);
}else  set_kb_item(name:"WMI/cps/RetentionDaysSec", value:val);

if(RetentionDaysEvent || RetentionDaysEvent == "0"){
  set_kb_item(name:"WMI/cps/RetentionDaysEvent", value:RetentionDaysEvent);
}else  set_kb_item(name:"WMI/cps/RetentionDaysEvent", value:val);

if(TicketValidateClient || TicketValidateClient == "0"){
  set_kb_item(name:"WMI/cps/TicketValidateClient", value:TicketValidateClient);
}else  set_kb_item(name:"WMI/cps/TicketValidateClient", value:val);

if(MaxClockSkew || MaxClockSkew == "0"){
  set_kb_item(name:"WMI/cps/MaxClockSkew", value:MaxClockSkew);
}else  set_kb_item(name:"WMI/cps/MaxClockSkew", value:val);

if(MaxServiceAge || MaxServiceAge == "0"){
  set_kb_item(name:"WMI/cps/MaxServiceAge", value:MaxServiceAge);
}else  set_kb_item(name:"WMI/cps/MaxServiceAge", value:val);

if(MaxRenewAge || MaxRenewAge == "0"){
  set_kb_item(name:"WMI/cps/MaxRenewAge", value:MaxRenewAge);
}else  set_kb_item(name:"WMI/cps/MaxRenewAge", value:val);

if(MaxTicketAge || MaxTicketAge == "0"){
  set_kb_item(name:"WMI/cps/MaxTicketAge", value:MaxTicketAge);
}else  set_kb_item(name:"WMI/cps/MaxTicketAge", value:val);

if(OverWritePolicyApp || OverWritePolicyApp == "0"){
  set_kb_item(name:"WMI/cps/OverWritePolicyApp", value:OverWritePolicyApp);
}else  set_kb_item(name:"WMI/cps/OverWritePolicyApp", value:val);

if(OverWritePolicySec || OverWritePolicySec == "0"){
  set_kb_item(name:"WMI/cps/OverWritePolicySec", value:OverWritePolicySec);
}else  set_kb_item(name:"WMI/cps/OverWritePolicySec", value:val);

if(OverWritePolicyEvent || OverWritePolicyEvent == "0"){
  set_kb_item(name:"WMI/cps/OverWritePolicyEvent", value:OverWritePolicyEvent);
}else  set_kb_item(name:"WMI/cps/OverWritePolicyEvent", value:val);



#---------------------------------------------------------
#previously GSHB_WMI_get_Shares.nasl

sharequery = 'select Name from Win32_Share';
SHARES = wmi_query(wmi_handle:handle, query:sharequery);

IPC = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Control\LSA", val_name:"RestrictAnonymous");
AUTOSHARE = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", val_name:"AutoShareServer");

if(!SHARES) SHARES = "None";
if(!IPC) IPC = "None";
if(AUTOSHARE == "0") AUTOSHARE = "NULL";
else AUTOSHARE = "None";

set_kb_item(name:"WMI/Shares", value:SHARES);
set_kb_item(name:"WMI/IPC", value:IPC);
set_kb_item(name:"WMI/AUTOSHARE", value:AUTOSHARE);

#---------------------------------------------------------
#previously GSHB_WMI_LM_comp_level.nasl

LMCOMPLEVELKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\control\Lsa");
LMCOMPLEVELKEY = tolower(LMCOMPLEVELKEY);

if(!LMCOMPLEVELKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Path not found.");
  set_kb_item(name:"WMI/LMCompatibilityLevel", value:"error");
#  wmi_close(wmi_handle:handlereg);
#  exit(0);
}else if ("lmcompatibilitylevel" >!< LMCOMPLEVELKEY){
  log_message(port:0, proto: "IT-Grundschutz", data:"Registry Value not found.");
  set_kb_item(name:"WMI/LMCompatibilityLevel", value:"error");
#  wmi_close(wmi_handle:handlereg);
#  exit(0);
}else {

  lmcomplevel = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SYSTEM\CurrentControlSet\control\Lsa", val_name:"LMCompatibilityLevel");

  if (lmcomplevel == "0" || lmcomplevel == 1)
  {
    set_kb_item(name:"WMI/LMCompatibilityLevel", value:"off");
  }
  else
  {
    set_kb_item(name:"WMI/LMCompatibilityLevel", value:"on");
  }
}

if (lmcomplevel =~ "[0-9]") set_kb_item(name:"WMI/scp/LMCompatibilityLevel", value:lmcomplevel);
else set_kb_item(name:"WMI/scp/LMCompatibilityLevel", value:"None");

#---------------------------------------------------------
#previously GSHB_WMI_Loginscreen.nasl

POLICIEKEY = wmi_reg_enum_value(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");

lastuser = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", val_name:"DontDisplayLastUserName");

lastuserpol = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", val_name:"DontDisplayLastUserName");

lenoca = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"LegalNoticeCaption");

lenocapol = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", key_name:"LegalNoticeCaption");

lenote = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", key_name:"LegalNoticeText");

lenotepol = wmi_reg_get_sz(wmi_handle:handlereg, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", key_name:"legalnoticetext");

if(!POLICIEKEY){
lastuserpol = 0;
lenocapol = "";
lenotepol = "";
}

if((lastuser == 1) || (lastuserpol == 1))
{
  set_kb_item(name:"WMI/DontDisplayLastUserName", value:"on");
}
else  {
      if((lastuser != 1) && (lastuserpol == 1))
              {
              set_kb_item(name:"WMI/DontDisplayLastUserName", value:"on");
              }
      else    {set_kb_item(name:"WMI/DontDisplayLastUserName", value:"off");
              }
}


if(lenoca >< "" && lenocapol >< "") {
  set_kb_item(name:"WMI/LegalNoticeCaption", value:"off");
}else{
set_kb_item(name:"WMI/LegalNoticeCaption", value:"on");
}

if(lenote >< "" && lenotepol >< "") {
  set_kb_item(name:"WMI/LegalNoticeText", value:"off");
}else{
  set_kb_item(name:"WMI/LegalNoticeText", value:"on");
}

#---------------------------------------------------------
#previously GSHB_WMI_RPC-SMBandLDAP.nasl

requiresignorseal = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"requiresignorseal");
requirestrongkey = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\Netlogon\Parameters", val_name:"requirestrongkey");
RequireSecuritySignatureWs = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", val_name:"RequireSecuritySignature");
RequireSecuritySignatureSvr = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"RequireSecuritySignature");
#enablesecuritysignature = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanManServer\Parameters", val_name:"enablesecuritysignature");
NoLMHash = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa", val_name:"NoLMHash");
NTLMMinClientSec = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa\MSV1_0", val_name:"NTLMMinClientSec");
if (NTLMMinClientSec != "0")NTLMMinClientSec = hex2dec(xvalue:NTLMMinClientSec);
NTLMMinServerSec = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Control\Lsa\MSV1_0", val_name:"NTLMMinServerSec");
if (NTLMMinServerSec != "0")NTLMMinServerSec = hex2dec(xvalue:NTLMMinServerSec);
LDAPClientIntegrity = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LDAP", val_name:"LDAPClientIntegrity");
EnablePlainTextPassword = wmi_reg_get_dword_val(wmi_handle:handlereg, key:"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", val_name:"EnablePlainTextPassword");


if(requiresignorseal || requiresignorseal == "0"){
  set_kb_item(name:"WMI/cps/requiresignorseal", value:requiresignorseal);
}else  set_kb_item(name:"WMI/cps/requiresignorseal", value:val);

if(requirestrongkey ||requirestrongkey == "0"){
  set_kb_item(name:"WMI/cps/requirestrongkey", value:requirestrongkey);
}else  set_kb_item(name:"WMI/cps/requirestrongkey", value:val);

if(RequireSecuritySignatureWs || RequireSecuritySignatureWs == "0"){
  set_kb_item(name:"WMI/cps/RequireSecuritySignatureWs", value:RequireSecuritySignatureWs);
}else  set_kb_item(name:"WMI/cps/RequireSecuritySignatureWs", value:val);

if(RequireSecuritySignatureSvr || RequireSecuritySignatureSvr == "0"){
  set_kb_item(name:"WMI/cps/RequireSecuritySignatureSvr", value:RequireSecuritySignatureSvr);
}else  set_kb_item(name:"WMI/cps/RequireSecuritySignatureSvr", value:val);

#if(enablesecuritysignature || enablesecuritysignature == "0"){
#  set_kb_item(name:"WMI/cps/enablesecuritysignature", value:enablesecuritysignature);
#}else  set_kb_item(name:"WMI/cps/enablesecuritysignature", value:val);

if(NoLMHash || NoLMHash == "0"){
  set_kb_item(name:"WMI/cps/NoLMHash", value:NoLMHash);
}else  set_kb_item(name:"WMI/cps/NoLMHash", value:val);

if(NTLMMinClientSec || NTLMMinClientSec == "0"){
  set_kb_item(name:"WMI/cps/NTLMMinClientSec", value:NTLMMinClientSec);
}else  set_kb_item(name:"WMI/cps/NTLMMinClientSec", value:val);

if(NTLMMinServerSec || NTLMMinServerSec == "0"){
  set_kb_item(name:"WMI/cps/NTLMMinServerSec", value:NTLMMinServerSec);
}else  set_kb_item(name:"WMI/cps/NTLMMinServerSec", value:val);

if(LDAPClientIntegrity || LDAPClientIntegrity == "0"){
  set_kb_item(name:"WMI/cps/LDAPClientIntegrity", value:LDAPClientIntegrity);
}else  set_kb_item(name:"WMI/cps/LDAPClientIntegrity", value:val);

if(EnablePlainTextPassword || EnablePlainTextPassword == "0"){
  set_kb_item(name:"WMI/cps/EnablePlainTextPassword", value:EnablePlainTextPassword);
}else  set_kb_item(name:"WMI/cps/EnablePlainTextPassword", value:val);

wmi_close(wmi_handle:handlereg);
wmi_close(wmi_handle:handlersop);
wmi_close(wmi_handle:handle);

set_kb_item(name:"WMI/cps/GENERAL", value:"ok");

exit(0);
