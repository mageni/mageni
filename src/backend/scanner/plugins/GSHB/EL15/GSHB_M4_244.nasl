###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_244.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 15. EL, Maßnahme 4.244
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.94221");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.244: Sichere Systemkonfiguration von Windows Client-Betriebssystemen.");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04244.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_list_Services.nasl", "GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_PasswdPolicie.nasl", "GSHB/GSHB_WMI_CD-Autostart.nasl", "GSHB/GSHB_WMI_XP-InetComm.nasl");
  script_require_keys("WMI/WMI_OSVER");
  script_tag(name:"summary", value:"IT-Grundschutz M4.244: Sichere Systemkonfiguration von Windows Client-Betriebssystemen.

Stand: 15. Ergänzungslieferung (15. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.244: Sichere Systemkonfiguration von Windows Client-Betriebssystemen\n';

gshbm =  "IT-Grundschutz M4.244: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");

AddPrinterDrivers = get_kb_item("WMI/cps/AddPrinterDrivers");
AllocateCDRoms = get_kb_item("WMI/cps/AllocateCDRoms");
AllocateDASD = get_kb_item("WMI/cps/AllocateDASD");
AllocateFloppies = get_kb_item("WMI/cps/AllocateFloppies");
AuditAccountLogon = get_kb_item("WMI/cps/AuditAccountLogon");
AuditAccountManage = get_kb_item("WMI/cps/AuditAccountManage");
AuditBaseObjects = get_kb_item("WMI/cps/AuditBaseObjects");
AuditDSAccess = get_kb_item("WMI/cps/AuditDSAccess");
AuditLogonEvents = get_kb_item("WMI/cps/AuditLogonEvents");
AuditObjectAccess = get_kb_item("WMI/cps/AuditObjectAccess");
AuditPolicyChange = get_kb_item("WMI/cps/AuditPolicyChange");
AuditPrivilegeUse = get_kb_item("WMI/cps/AuditPrivilegeUse");
AuditProcessTracking = get_kb_item("WMI/cps/AuditProcessTracking");
AuditSystemEvents = get_kb_item("WMI/cps/AuditSystemEvents");
autodisconnect = get_kb_item("WMI/cps/autodisconnect");
cachedlogonscount = get_kb_item("WMI/cps/cachedlogonscount");
ClearPageFileAtShutdown = get_kb_item("WMI/cps/ClearPageFileAtShutdown");
ClearTextPassword = get_kb_item("WMI/lockoutpolicy/ClearTextPassword");
if (!ClearTextPassword)ClearTextPassword = "None";
crashonauditfail = get_kb_item("WMI/cps/crashonauditfail");
DisableCAD = get_kb_item("WMI/cps/DisableCAD");
DisableDomainCreds = get_kb_item("WMI/cps/DisableDomainCreds");
disablepasswordchange = get_kb_item("WMI/cps/disablepasswordchange");
enableforcedlogoff = get_kb_item("WMI/cps/enableforcedlogoff");
EnablePlainTextPassword = get_kb_item("WMI/cps/EnablePlainTextPassword");
EnableSecuritySignatureWs = get_kb_item("WMI/cps/EnableSecuritySignatureWs");
EnableSecuritySignatureSvr = get_kb_item("WMI/cps/EnableSecuritySignatureSvr");
EveryoneIncludesAnonymous = get_kb_item("WMI/cps/EveryoneIncludesAnonymous");
FIPSAlgorithmPolicy = get_kb_item("WMI/cps/FIPSAlgorithmPolicy");
ForceGuest = get_kb_item("WMI/cps/ForceGuest");
ForceUnlockLogon = get_kb_item("WMI/cps/ForceUnlockLogon");
fullprivilegeauditing = get_kb_item("WMI/cps/fullprivilegeauditing");
LDAPClientIntegrity = get_kb_item("WMI/cps/LDAPClientIntegrity");
ldapserverintegrity = get_kb_item("WMI/cps/ldapserverintegrity");
LimitBlankPasswordUse = get_kb_item("WMI/cps/LimitBlankPasswordUse");
LmCompatibilityLevel = get_kb_item("WMI/scp/LMCompatibilityLevel");
LockoutBadCount = get_kb_item("WMI/passwdpolicy/LockoutBadCount");
if (!LockoutBadCount)LockoutBadCount = "None";
LockoutDuration = get_kb_item("WMI/passwdpolicy/LockoutDuration");
if (!LockoutDuration)LockoutDuration = "None";
LSAAnonymousNameLookup = get_kb_item("WMI/cps/LSAAnonymousNameLookup");
MachinePaths = get_kb_item("WMI/cps/MachinePaths");
MaximumLogSizeApp = get_kb_item("WMI/cps/MaximumLogSizeApp");
MaximumLogSizeEvent = get_kb_item("WMI/cps/MaximumLogSizeEvent");
MaximumLogSizeSec = get_kb_item("WMI/cps/MaximumLogSizeSec");
MaximumPasswordAge = get_kb_item("WMI/passwdpolicy/MaximumPasswordAge");
if (!PasswordComplexity)PasswordComplexity = "None";
maximumComppasswordage = get_kb_item("WMI/cps/maximumComppasswordage");
MinimumPasswordAge = get_kb_item("WMI/passwdpolicy/MinimumPasswordAge");
if (!MinimumPasswordAge)MinimumPasswordAge = "None";
MinimumPasswordLength = get_kb_item("WMI/passwdpolicy/MinimumPasswordLength");
if (!MinimumPasswordLength)MinimumPasswordLength = "None";
nodefaultadminowner = get_kb_item("WMI/cps/nodefaultadminowner");
NoLMHash = get_kb_item("WMI/cps/NoLMHash");
NTLMMinClientSec = get_kb_item("WMI/cps/NTLMMinClientSec");
NTLMMinServerSec = get_kb_item("WMI/cps/NTLMMinServerSec");
NullSessionPipes = get_kb_item("WMI/cps/NullSessionPipes");
NullSessionShares = get_kb_item("WMI/cps/NullSessionShares");
ObCaseInsensitive = get_kb_item("WMI/cps/ObCaseInsensitive");
OverWritePolicyApp = get_kb_item("WMI/cps/OverWritePolicyApp");
OverWritePolicySec = get_kb_item("WMI/cps/OverWritePolicySec");
OverWritePolicyEvent = get_kb_item("WMI/cps/OverWritePolicyEvent");
PasswordComplexity = get_kb_item("WMI/lockoutpolicy/PasswordComplexity");
if (!PasswordComplexity)PasswordComplexity = "None";
passwordexpirywarning = get_kb_item("WMI/cps/passwordexpirywarning");
PasswordHistorySize = get_kb_item("WMI/passwdpolicy/PasswordHistorySize");
if (PasswordHistorySize)PasswordHistorySize = int(PasswordHistorySize);
else PasswordHistorySize = "None";
Policy = get_kb_item("WMI/cps/Policy");
ProtectionMode = get_kb_item("WMI/cps/ProtectionMode");
RequireSecuritySignatureWs = get_kb_item("WMI/cps/RequireSecuritySignatureWs");
RequireSecuritySignatureSvr = get_kb_item("WMI/cps/RequireSecuritySignatureSvr");
requiresignorseal = get_kb_item("WMI/cps/requiresignorseal");
requirestrongkey = get_kb_item("WMI/cps/requirestrongkey");
ResetLockoutCount = get_kb_item("WMI/passwdpolicy/ResetLockoutCount");
if (!ResetLockoutCount)ResetLockoutCount = "None";
RestrictAnonymous = get_kb_item("WMI/cps/RestrictAnonymous");
RestrictAnonymousSAM = get_kb_item("WMI/cps/RestrictAnonymousSAM");
RestrictGuestAccessApp = get_kb_item("WMI/cps/RestrictGuestAccessApp");
RestrictGuestAccessEvent = get_kb_item("WMI/cps/RestrictGuestAccessEvent");
RestrictGuestAccessSec = get_kb_item("WMI/cps/RestrictGuestAccessSec");
scremoveoption = get_kb_item("WMI/cps/scremoveoption");
sealsecurechannel = get_kb_item("WMI/cps/sealsecurechannel");
securitylevel = get_kb_item("WMI/cps/securitylevel");
setcommand = get_kb_item("WMI/cps/setcommand");
ShutdownWithoutLogon = get_kb_item("WMI/cps/ShutdownWithoutLogon");
signsecurechannel = get_kb_item("WMI/cps/signsecurechannel");
undockwithoutlogon = get_kb_item("WMI/cps/undockwithoutlogon");

NoUpdateCheck = get_kb_item("WMI/XP-InetComm/NoUpdateCheck");
PreventAutoRun = get_kb_item("WMI/XP-InetComm/PreventAutoRun");
EnabledNTPServer = get_kb_item("WMI/XP-InetComm/EnabledNTPServer");
Headlines = get_kb_item("WMI/XP-InetComm/Headlines");
DisableWindowsUpdateAccess = get_kb_item("WMI/XP-InetComm/DisableWindowsUpdateAccess");
DontSearchWindowsUpdate = get_kb_item("WMI/XP-InetComm/DontSearchWindowsUpdate");
NoRegistration = get_kb_item("WMI/XP-InetComm/NoRegistration");
DisableRootAutoUpdate = get_kb_item("WMI/XP-InetComm/DisableRootAutoUpdate");
MicrosoftEventVwrDisableLinks = get_kb_item("WMI/XP-InetComm/MicrosoftEventVwrDisableLinks");
NoInternetOpenWith = get_kb_item("WMI/XP-InetComm/NoInternetOpenWith");
DoReport = get_kb_item("WMI/XP-InetComm/DoReport");

DontDisplayLastUserName = get_kb_item("WMI/DontDisplayLastUserName");
SHARES = get_kb_item("WMI/Shares");
IPC = get_kb_item("WMI/IPC");
AUTOSHARE = get_kb_item("WMI/AUTOSHARE");
LegalNoticeCaption = get_kb_item("WMI/LegalNoticeCaption");
LegalNoticeText = get_kb_item("WMI/LegalNoticeText");
CDAutostart = get_kb_item("WMI/CD_Autostart");
WindowsStore = get_kb_item("WMI/Win8Policies/WindowsStore");
HandwritingRecognition1 = get_kb_item("WMI/Win8Policies/HandwritingRecognition1");
HandwritingRecognition2 = get_kb_item("WMI/Win8Policies/HandwritingRecognition2");


servicelist = "
alerter|disabled
alg|disabled
appmgmt|disabled
aspnet_state|manual
audiosrv|auto
bits|manual
browser|disabled
cisvc|disabled
clipsrv|disabled
comsysapp|manual
cryptsvc|auto
dhcp|auto
dmadmin|manual
dmserver|manual
dnscache|auto
ersvc|disabled
eventlog|auto
eventsystem|manual
fastuserswitchingcompatibility|disabled
fax|disabled
helpsvc|auto
hidserv|disabled
httpfilter|disabled
iisadmin|disabled
imapiservice|disabled
irmon|disabled
lanmanserver|auto
lanworkstation|auto
lmhosts|auto
messenger|disabled
mnmsrvc|disabled
msdtc|disabled
msftpsvc|disabled
msiserver|manual
netdde|disabled
netddedsdm|disabled
netlogon|auto
netman|manual
nla|manual
ntlmssp|manual
ntmssvc|disabled
plugplay|auto
policyagent|disabled
protectedstorage|auto
rasauto|disabled
rasman|disabled
rdsessmgr|disabled
remoteaccess|disabled
remoteregistry|auto
rpclocator|manual
rpcss|auto
rsvp|manual
samss|auto
scardsvr|manual
schedule|manual
seclogon|auto
sens|auto
sharedaccess|disabled
spooler|auto
srservice|disabled
ssdpsrv|manual
stisvc|manual
swprv|disabled
sysmonlog|manual
tapisrv|manual
termservice|manual
themes|disabled
tlntsvr|disabled
trkwks|disabled
uploadmgr|auto
upnphost|disabled
ups|manual
vss|disabled
w32time|auto
w3svc|disabled
webclient|disabled
windefend|disabled
winmgmt|auto
wmdmpmsn|disabled
wmi|manual
wmiapsrv|manual
wuauserv|auto
wzcsvc|disabled
";

ServiveNameList ="
Servicename@Service Displayname
alerter@Warndienst
alg@Gatewaydienst auf Anwendungsebene
appmgmt@Anwendungsverwaltung
aspnet_state@ASP.NET-Statusdienst
audiosrv@Windows Audio
bits@Intelligenter Hintergrundübertragungsdienst
browser@Computerbrowser
cisvc@Indexdienst
clipsrv@Ablagemappe
comsysapp@COM+ Systemanwendung
cryptsvc@Kryptografiedienste
dhcp@DHCP-Client
dmadmin@Verwaltungsdienst für die Verwaltung logischer Datenträger
dmserver@Verwaltung logischer Datenträger
dnscache@DNS-Client
ersvc@Fehlerberichterstattungsdienst
eventlog@Ereignisprotokoll
eventsystem@COM+ Eriegnissystem
fastuserswitchingcompatibility @Kompatibilität für schnelle Benutzerumschaltung
fax@Fax Service
helpsvc@Hilfe and Support
hidserv@Eingabegerätezugang
httpfilter@HTTP-SSL
iisadmin@IIS-Verwaltungsdienst
imapiservice@IMAPI-CD-Brenn-COM-Dienste
irmon@Infrarotüberwachung
lanmanserver@Server
lanworkstation@Arbeitsstationsdienst
lmhosts@TCP/IP-NetBIOS-Hilfsprogramm
messenger@Nachrichtendienst
mnmsrvc@NetMeeting-Remotedesktop-Freigabe
msdtc@Distributed Transaction Coordinator
msftpsvc@FTP-Publishing-Dienst
msiserver@Windows Installer
netdde@Netzwerk-DDE-Dienst
netddedsdm@Netzwerk-DDE-Serverdienst
netlogon@Anmeldedienst
netman@Netzwerkverbindungen
nla@NLA (Network Location Awareness)
ntlmssp@NT-LM-Sicherheitsdienst
ntmssvc@Wechselmedien
plugplay@Plug & Play
policyagent@IPSec-Dienste
protectedstorage@Geschützter Speicher
rasauto@Verwaltung für automatische RAS-Verbindung
rasman@RAS-Verbindungsverwaltung
rdsessmgr@Sitzungs-Manager für Remotedesktop
remoteaccess@Routing and RAS
remoteregistry@Remote-Registrierung
rpclocator@RPC-Locator
rpcss@Remoteprozeduraufruf (RPC)
rsvp@QoS-RSVP
samss@Sicherheitskontenverwaltung
scardsvr@Smartcard
schedule@Taskplaner
seclogon@Sekundäre Anmeldung
sens@Systemereignisbenachrichtigung
sharedaccess@Windows-Firewall/Gemeinsame Nutzung der Internetverbindung
spooler@Druckwarteschlange
srservice@Systemwiederherstellungsdienst
ssdpsrv@SSDP-Suchdienst
stisvc@Windows Bilderfassung (WIA)
swprv@MS Software Shadow Copy Provider
sysmonlog @Leistungsdatenprotokolle und Warnungen
tapisrv@Telefonie
termservice@Terminaldienste
themes@Designs
tlntsvr@Telnet
trkwks@Überwachung verteilter Verknüpfungen (Client)
uploadmgr@Upload-Manager
upnphost@Universeller Plug & Play-Gerätehost
ups@Unterbrechungsfreie Stromversorgung
vss@Volumenschattenkopie
w32time@Windows-Zeitgeber
w3svc@WWW-Publishing-Dienst
webclient@WebClient
windefend@Windows Defender
winmgmt@Windows-Verwaltungsadministration
wmdmpmsn @Dienst für Seriennummern der tragbaren Medien
wmi@Treibererweiterungen für Windows-Verwaltungsinstrumentation
wmiapsrv@WMI-Leistungsadapter
wuauserv@Automatische Updates
wzcsvc@Konfigurationsfreie drahtlose Verbindung
";

ServiceStartmode = get_kb_item("WMI/ServiceStartmode");

if (ServiceStartmode != "None")
{
  ServiceStartmode = tolower(ServiceStartmode);
  ServiceStartmode = split(ServiceStartmode, sep:'\n', keep:0);
}

for (c=1; c<max_index(ServiceStartmode); c++)
{
      Servicename = split(ServiceStartmode[c], sep:'|', keep:0);
      Service = egrep(pattern:Servicename[0], string:servicelist );
      Service = split(Service, sep:'\n', keep:0);
      if (!Service[0])continue;

      if (Service[0] != ServiceStartmode[c])
      {
        ServiceTest = egrep(pattern:Servicename[0], string:ServiveNameList );
        ServiceTest = ereg_replace(pattern:'(.*)@',replace:'', string:ServiceTest);
        ServiceTest = ereg_replace(pattern:'\n',replace:'', string:ServiceTest);
        ServiceFailList = ServiceFailList + ServiceTest + '\n';
      }
}
if (!ServiceFailList) ServiceFailList = "None";

if (LSAAnonymousNameLookup != "None")
{
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup, sep:'\n', keep:0);
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup[1], sep:'|', keep:0);
}

if (RestrictGuestAccessApp != "None")
{
  RestrictGuestAccessApp = split(RestrictGuestAccessApp, sep:'\n', keep:0);
  RestrictGuestAccessApp = split(RestrictGuestAccessApp[1], sep:'|', keep:0);
}

if (RestrictGuestAccessEvent != "None")
{
  RestrictGuestAccessEvent = split(RestrictGuestAccessEvent, sep:'\n', keep:0);
  RestrictGuestAccessEvent = split(RestrictGuestAccessEvent[1], sep:'|', keep:0);
}

if (RestrictGuestAccessSec != "None")
{
  RestrictGuestAccessSec = split(RestrictGuestAccessSec, sep:'\n', keep:0);
  RestrictGuestAccessSec = split(RestrictGuestAccessSec[1], sep:'|', keep:0);
}

if (OverWritePolicyApp != "None")
{
  OverWritePolicyApp = split(OverWritePolicyApp, sep:'\n', keep:0);
  OverWritePolicyApp = split(OverWritePolicyApp[1], sep:'|', keep:0);
}

if (OverWritePolicyEvent != "None")
{
  OverWritePolicyEvent = split(OverWritePolicyEvent, sep:'\n', keep:0);
  OverWritePolicyEvent = split(OverWritePolicyEvent[1], sep:'|', keep:0);
}

if (OverWritePolicySec != "None")
{
  OverWritePolicySec = split(OverWritePolicySec, sep:'\n', keep:0);
  OverWritePolicySec = split(OverWritePolicySec[1], sep:'|', keep:0);
}

if (AuditAccountLogon != "None")
{
  AuditAccountLogon = split(AuditAccountLogon, sep:'\n', keep:0);
  AuditAccountLogon = split(AuditAccountLogon[1], sep:'|', keep:0);
}

if (AuditAccountManage != "None")
{
  AuditAccountManage = split(AuditAccountManage, sep:'\n', keep:0);
  AuditAccountManage = split(AuditAccountManage[1], sep:'|', keep:0);
}

if (AuditDSAccess != "None")
{
  AuditDSAccess = split(AuditDSAccess, sep:'\n', keep:0);
  AuditDSAccess = split(AuditDSAccess[1], sep:'|', keep:0);
}

if (AuditLogonEvents != "None")
{
  AuditLogonEvents = split(AuditLogonEvents, sep:'\n', keep:0);
  AuditLogonEvents = split(AuditLogonEvents[1], sep:'|', keep:0);
}

if (AuditObjectAccess != "None")
{
  AuditObjectAccess = split(AuditObjectAccess, sep:'\n', keep:0);
  AuditObjectAccess = split(AuditObjectAccess[1], sep:'|', keep:0);
}

if (AuditPolicyChange != "None")
{
  AuditPolicyChange = split(AuditPolicyChange, sep:'\n', keep:0);
  AuditPolicyChange = split(AuditPolicyChange[1], sep:'|', keep:0);
}

if (AuditPrivilegeUse != "None")
{
  AuditPrivilegeUse = split(AuditPrivilegeUse, sep:'\n', keep:0);
  AuditPrivilegeUse = split(AuditPrivilegeUse[1], sep:'|', keep:0);
}

if (AuditProcessTracking != "None")
{
  AuditProcessTracking = split(AuditProcessTracking, sep:'\n', keep:0);
  AuditProcessTracking = split(AuditProcessTracking[1], sep:'|', keep:0);
}

if (AuditSystemEvents != "None")
{
  AuditSystemEvents = split(AuditSystemEvents, sep:'\n', keep:0);
  AuditSystemEvents = split(AuditSystemEvents[1], sep:'|', keep:0);
}
if (MaximumLogSizeApp != "None")

{
  MaximumLogSizeApp = split(MaximumLogSizeApp, sep:'\n', keep:0);
  MaximumLogSizeApp = split(MaximumLogSizeApp[1], sep:'|', keep:0);
  MaximumLogSizeApp = MaximumLogSizeApp[2];
}
if (MaximumLogSizeEvent != "None")

{
  MaximumLogSizeEvent = split(MaximumLogSizeEvent, sep:'\n', keep:0);
  MaximumLogSizeEvent = split(MaximumLogSizeEvent[1], sep:'|', keep:0);
  MaximumLogSizeEvent = MaximumLogSizeEvent[2];
}
if (MaximumLogSizeSec != "None")

{
  MaximumLogSizeSec = split(MaximumLogSizeSec, sep:'\n', keep:0);
  MaximumLogSizeSec = split(MaximumLogSizeSec[1], sep:'|', keep:0);
  MaximumLogSizeSec = MaximumLogSizeSec[2];
}

if (WindowsStore != "None" ){
  WindowsStore = split(WindowsStore, sep:'\n', keep:0);
  WindowsStore = split(WindowsStore[1], sep:'|', keep:0);
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba,\nes ist kein Microsoft Windows System.");
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgeführt werden.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(OSVER < '5.1' || ( OSVER == '5.2' && OSNAME >!< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER > '5.2' && OSTYPE != '1')){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Client-Betriebssystem.");
}else if(AddPrinterDrivers == "1" &&  AllocateCDRoms == "1" &&  AllocateDASD == "2" &&  AllocateFloppies == "1" &&  AuditAccountLogon[1] == "True" &&  AuditAccountLogon[3] == "True" &&  AuditAccountManage[1] == "True" &&  AuditAccountManage[3] == "True" &&  AuditBaseObjects == "0" &&  AuditLogonEvents[1] == "True" &&  AuditLogonEvents[3] == "True" &&  AuditObjectAccess[1] == "True" &&  AuditPolicyChange[1] == "True" &&  AuditPolicyChange[3] == "True" &&  AuditPrivilegeUse[1] == "True" &&  AuditSystemEvents[1] == "True" &&  AuditSystemEvents[3] == "True" &&  autodisconnect == "15" &&  cachedlogonscount == "0" &&  ClearPageFileAtShutdown == "1" &&  ClearTextPassword == "False" &&  crashonauditfail == "0" &&  DisableCAD == "0" &&  DisableDomainCreds == "1" &&  disablepasswordchange == "0" &&  DontDisplayLastUserName == "on" &&  enableforcedlogoff == "1" &&  EnablePlainTextPassword == "0" &&  EnableSecuritySignatureSvr == "1" &&  EnableSecuritySignatureWs == "1" &&  EveryoneIncludesAnonymous == "0" &&  FIPSAlgorithmPolicy == "0" &&  ForceGuest == "0" &&  ForceUnlockLogon == "1" &&  fullprivilegeauditing == "0" &&  LDAPClientIntegrity == "1" &&  ldapserverintegrity == "2" &&  LegalNoticeCaption == "on" &&  LegalNoticeText == "on" &&  LimitBlankPasswordUse == "1" &&  LmCompatibilityLevel == "5" &&  LockoutBadCount == "3" &&  LockoutDuration == "4294967295" &&  LSAAnonymousNameLookup == "False" &&  MachinePaths == "Empty" && maximumComppasswordage <= 30 &&  MaximumLogSizeApp >= 30080 &&  MaximumLogSizeEvent >= 30080 &&  MaximumLogSizeSec >= 100992 &&  MaximumPasswordAge <= 90 && MinimumPasswordAge == "1" &&  MinimumPasswordLength >= 8 &&  nodefaultadminowner == "1" &&  NoLMHash == "1" &&  NTLMMinClientSec == "537395248" &&  NTLMMinServerSec == "537395248" &&  NullSessionPipes == "Empty" &&  NullSessionShares == "Empty" &&  ObCaseInsensitive == "1" &&  (OverWritePolicyApp[1] == "Bei Bedarf" || OverWritePolicyApp[1] == "WhenNeeded") &&  (OverWritePolicyEvent[1] == "Bei Bedarf" || OverWritePolicyEvent[1] == "WhenNeeded") &&  (OverWritePolicySec[1] == "Bei Bedarf" || OverWritePolicySec[1] == "WhenNeeded") &&  PasswordComplexity == "True" &&  passwordexpirywarning == "14" &&  PasswordHistorySize >= 6 &&  Policy == "1" &&  ProtectionMode == "1" &&  RequireSecuritySignatureSvr == "1" &&  RequireSecuritySignatureWs == "1" &&  requiresignorseal == "1" &&  requirestrongkey == "1" &&  ResetLockoutCount >= 30 &&  RestrictAnonymous == "1" &&  RestrictAnonymousSAM == "1" &&  RestrictGuestAccessApp == "True" &&  RestrictGuestAccessEvent == "True" &&  RestrictGuestAccessSec == "True" &&  scremoveoption == "1" &&  sealsecurechannel == "1" &&  securitylevel == "0" &&  setcommand == "0" &&  ShutdownWithoutLogon == "0" &&  signsecurechannel == "1" && undockwithoutlogon == "0" && ServiceFailList == "None" && CDAutostart == "off" && NoUpdateCheck == "1" && PreventAutoRun == "1" && EnabledNTPServer == "0" && Headlines == "0" && DisableWindowsUpdateAccess == "1" && DontSearchWindowsUpdate == "1" && NoRegistration == "1" && DisableRootAutoUpdate == "1" && MicrosoftEventVwrDisableLinks == "1" && NoInternetOpenWith == "1" && DoReport == "0" && WindowsStore == "1" && HandwritingRecognition1 == "1" && HandwritingRecognition2 == "1")
{
  result = string("erfüllt");
  desc = string('\nDie Sicherheitseinstellung stimmen mit der Maßnahme\nM4.224 überein. Bitte überprüfen Sie weiterhin, ob\nfolgende Domainpolicies richtig konfiguriert sind:\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\Abruf von\nMedieninformationen zu Musikdateien verhinden\n\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\\nBenutzeroberfläche\\Design festlegen und fixieren\n\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\Wiedergabe\\\nCodec-Download verhindern\n\nBitte prüfen Sie, ob der Einsatz von AppLocker hilfreich sein kann.\n\nBitte beachten Sie auch das Kapitel -Restriktive\nBerechtigungsvergabe unter Windows XP- aus dem\nDokument -Konfigurations- und Sicherheitseinstellungen\nunter Windows XP-. Zu finden unter: https://www.bsi.\nbund.de/cae/servlet/contentblob/471594/\npublicationFile/31046/Hilfsmittel_Windows_XP_pdf.pdf');
}else
{
  result = string("nicht erfüllt");
  if (ServiceFailList != "None")val = ServiceFailList;
  if (CDAutostart == "on")  val = val + '\n\n' + "CD-ROM Autoplay-Funktionalität: " + CDAutostart;
  if (WindowsStore != "1") val = val + '\n\n' + "Windows Store ist nicht deaktiviert (kein Registry-Key: HKLM\Software\Policies\Microsoft\WindowsStore!DisableStoreApps=DWORD(1) vorhanden).";
  if (HandwritingRecognition1 != "1" || HandwritingRecognition2 != "1") val = val + '\n\n' + 'Handschrifterkennung ist nicht deaktiviert (keine Registry-Keys:\n HKLM\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization[RestrictImplicitTextCollection|RestrictImplicitInkCollection] 0 DWORD(1) vorhanden.';
  if (AddPrinterDrivers != "1") val = val + '\n\n' + "Geräte: Anwendern das Installieren von Druckertreibern\nnicht erlauben: " + AddPrinterDrivers;
  if (AllocateCDRoms != "1") val = val + '\n\n' + "Geräte: Zugriff auf CD-ROM-Laufwerke auf lokal ange-\nmeldete Benutzer beschränken: " + AllocateCDRoms;
  if (AllocateDASD != "2") val = val + '\n\n' + "Geräte: Formatieren und Auswerfen von Wechselmedien\nzulassen: " + AllocateDASD;
  if (AllocateFloppies != "1") val = val + '\n\n' + "Geräte: Zugriff auf Diskettenlaufwerke auf lokal ange-\nmeldete Benutzer beschränken: " + AllocateFloppies;
  if (AuditAccountLogon >< "None")val = val + '\n\n' + "Anmeldeversuche überwachen: " + AuditAccountLogon;
  else{
    if (AuditAccountLogon[1] != "True") val = val + '\n\n' + "Anmeldeversuche überwachen Fehlgeschlagen: " + AuditAccountLogon[1];
    if (AuditAccountLogon[3] != "True") val = val + '\n\n' + "Anmeldeversuche überwachen Erfolgreich: " + AuditAccountLogon[3];
  }
  if (AuditAccountManage >< "None") val = val + '\n\n' + "Kontenverwaltung überwachen: " + AuditAccountManage;
  else{
    if (AuditAccountManage[1] != "True") val = val + '\n\n' + "Kontenverwaltung überwachen Fehlgeschlagen: " + AuditAccountManage[1];
    if (AuditAccountManage[3] != "True") val = val + '\n\n' + "Kontenverwaltung überwachen Erfolgreich: " + AuditAccountManage[3];
  }
  if (AuditBaseObjects != "0") val = val + '\n\n' + "Überwachung: Zugriff auf globale Systemobjekte\nprüfen: " + AuditBaseObjects;
  if (AuditLogonEvents >< "None") val = val + '\n\n' + "Anmeldeereignisse überwachen: " + AuditLogonEvents;
  else{
    if (AuditLogonEvents[1] != "True") val = val + '\n\n' + "Anmeldeereignisse überwachen Fehlgeschlagen: " + AuditLogonEvents[1];
    if (AuditLogonEvents[3] != "True") val = val + '\n\n' + "Anmeldeereignisse überwachen Erfolgreich: " + AuditLogonEvents[3];
  }
  if (AuditObjectAccess >< "None")  val = val + '\n\n' + "Objektzugriffsversuche überwachen: " + AuditObjectAccess;
  else{
      if (AuditObjectAccess[1] != "True") val = val + '\n\n' + "Objektzugriffsversuche überwachen: " + AuditObjectAccess[1];
  }
  if (AuditPolicyChange >< "None") val = val + '\n\n' + "Richtlinienänderungen überwachen: " + AuditPolicyChange;
  else{
    if (AuditPolicyChange[1] != "True") val = val + '\n\n' + "Richtlinienänderungen überwachen Fehlgeschlagen: " + AuditPolicyChange[1];
    if (AuditPolicyChange[3] != "True") val = val + '\n\n' + "Richtlinienänderungen überwachen Erfolgreich: " + AuditPolicyChange[3];
  }
  if (AuditPrivilegeUse >< "None") val = val + '\n\n' + "Rechteverwendung überwachen: " + AuditPrivilegeUse;
  else {
    if (AuditPrivilegeUse[1] != "True") val = val + '\n\n' + "Rechteverwendung überwachen: " + AuditPrivilegeUse[1];
  }
  if (AuditSystemEvents >< "None") val = val + '\n\n' + "Systemereignisse überwachen: " + AuditSystemEvents;
  else{
    if (AuditSystemEvents[1] != "True") val = val + '\n\n' + "Systemereignisse überwachen Fehlgeschlagen: " + AuditSystemEvents[1];
    if (AuditSystemEvents[3] != "True") val = val + '\n\n' + "Systemereignisse überwachen Erfolgreich: " + AuditSystemEvents[3];
  }
  if (autodisconnect != "15") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Leerlaufzeitspanne bis\nzum Anhalten der Sitzung: " + autodisconnect;
  if (cachedlogonscount != "0") val = val + '\n\n' + "Interaktive Anmeldung: Anzahl zwischenzuspeichernder\nvorheriger Anmeldungen (für den Fall, dass der\nDomänencontroller nicht verfügbar ist): " + cachedlogonscount;
  if (ClearPageFileAtShutdown != "1") val = val + '\n\n' + "Herunterfahren: Auslagerungsdatei des virtuellen\nArbeitspeichers löschen: " + ClearPageFileAtShutdown;
  if (ClearTextPassword != "False") val = val + '\n\n' + "Kennwörtern für alle Domänenbenutzer mit umkehrbarer\nVerschlüsselung speichern: " + ClearTextPassword;
  if (crashonauditfail != "0") val = val + '\n\n' + "Überwachung: System sofort herunterfahren, wenn\nSicherheitsüberprüfungen nicht protokolliert werden\nkönnen: " + crashonauditfail;
  if (DisableCAD != "0") val = val + '\n\n' + "Interaktive Anmeldung: Kein STRG+ALT+ENTF\nerforderlich: " + DisableCAD;
  if (DisableDomainCreds != "1") val = val + '\n\n' + "Netzwerkzugriff: Speicherung von Anmeldeinformationen\noder .NET-Passports für die Netzwerkauthentifikation\nnicht erlauben: " + DisableDomainCreds;
  if (disablepasswordchange != "0") val = val + '\n\n' + "Domänenmitglied: Änderungen von Computerkontenkenn-\nwörtern deaktivieren: " + disablepasswordchange;
  if (DontDisplayLastUserName != "on") val = val + '\n\n' + "Interaktive Anmeldung: Letzten Benutzernamen nicht\nanzeigen: " + DontDisplayLastUserName;
  if (enableforcedlogoff != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Clientverbindungen\naufheben, wenn die Anmeldezeit überschritten wird: " + enableforcedlogoff;
  if (EnablePlainTextPassword != "0") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Unverschlüsseltes Kenn-\nwort an SMB-Server von Drittanbietern senden: " + EnablePlainTextPassword;
  if (EnableSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Kommunikation digital\nsignieren (wenn Server zustimmt): " + EnableSecuritySignatureSvr;
  if (EnableSecuritySignatureWs != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital sig-\nnieren (wenn Client zustimmt): " + EnableSecuritySignatureWs;
  if (EveryoneIncludesAnonymous != "0") val = val + '\n\n' + "Netzwerkzugriff: Die Verwendung von 'Jeder'-Berechti-\ngungen für anonyme Benutzer ermöglichen: " + EveryoneIncludesAnonymous;
  if (FIPSAlgorithmPolicy != "0") val = val + '\n\n' + "Systemkryptografie: FIPS-konformen Algorithmus für\nVerschlüsselung, Hashing und Signatur verwenden: " + FIPSAlgorithmPolicy;
  if (ForceGuest != "0") val = val + '\n\n' + "Netzwerkzugriff: Modell für gemeinsame Nutzung und\nSicherheitsmodellfür lokale Konten: " + ForceGuest;
  if (ForceUnlockLogon != "1") val = val + '\n\n' + "Interaktive Anmeldung: Domänencontrollerauthenti-\nfizierung zum Aufheben der Sperrung der Arbeitsstation\nerforderlich: " + ForceUnlockLogon;
  if (fullprivilegeauditing != "0") val = val + '\n\n' + "Überwachung: Die Verwendung des Sicherungs- und Wieder-\nherstellungsrechts überprüfen: " + fullprivilegeauditing;
  if (LDAPClientIntegrity != "1") val = val + '\n\n' + "Netzwerksicherheit: Signaturanforderungen für LDAP-\nClients: " + LDAPClientIntegrity;
  if (ldapserverintegrity != "2") val = val + '\n\n' + "Domänencontroller: Signaturanforderungen für\nLDAP-Server: " + ldapserverintegrity;
  if (LegalNoticeCaption != "on") val = val + '\n\n' + "Interaktive Anmeldung: Nachrichtentitel für Benutzer,\ndie sich anmelden wollen: " + LegalNoticeCaption;
  if (LegalNoticeText != "on") val = val + '\n\n' + "Interaktive Anmeldung: Nachricht für Benutzer, die\nsich anmelden wollen: " + LegalNoticeText;
  if (LimitBlankPasswordUse != "1") val = val + '\n\n' + "Konten: Lokale Kontenverwendung von leeren Kennwörtern\nauf Konsolenanmeldung beschränken: " + LimitBlankPasswordUse;
  if (LmCompatibilityLevel != "5") val = val + '\n\n' + "Netzwerksicherheit: LAN Manager-\nAuthentifizierungsebene: " + LmCompatibilityLevel;
  if (LockoutBadCount != "3") val = val + '\n\n' + "Kontensperrungsschwelle: " + LockoutBadCount;
  if (LockoutDuration != "4294967295") val = val + '\n\n' + "Kontosperrdauer: " + LockoutDuration;
  if (LSAAnonymousNameLookup >< "None") val = val + '\n\n' + "Netzwerkzugriff: Anonyme SID-/Namensübersetzung\nzulassen: " + LSAAnonymousNameLookup;
  else{
    if (LSAAnonymousNameLookup[2] != "False") val = val + '\n\n' + "Netzwerkzugriff: Anonyme SID-/Namensübersetzung\nzulassen: " + LSAAnonymousNameLookup[2];
  }
  if (MachinePaths != "Empty"){
    MachinePaths = split(MachinePaths, sep:'|', keep:0);
    for(i=0; i<max_index(MachinePaths); i++)
    {
      MachinePathsval += MachinePaths[i] + ';\n';
    }
    val = val + '\n\n' + "Netzwerkzugriff: Registrierungspfade, auf die von\nanderen Computern aus zugegriffen werden kann:\n" + MachinePathsval;
  }
  if (maximumComppasswordage > 30) val = val + '\n\n' + "Domänenmitglied: Maximalalter von Computerkontenkenn-\nwörtern: " + maximumComppasswordage;
  if (MaximumLogSizeApp < 30080) val = val + '\n\n' + "Maximale Größe des Anwendungsprotokolls: " + MaximumLogSizeApp;
  if (MaximumLogSizeEvent < 30080) val = val + '\n\n' + "Maximale Größe des Systemprotokolls: " + MaximumLogSizeEvent;
  if (MaximumLogSizeSec < 100992) val = val + '\n\n' + "Maximale Größe des Sicherheitsprotokolls: " + MaximumLogSizeSec;
  if (MaximumPasswordAge > 90) val = val + '\n\n' + "Maximales Kennwortalter: " + MaximumPasswordAge;
  if (MinimumPasswordAge != "1") val = val + '\n\n' + "Minimales Kennwortalter: " + MinimumPasswordAge;
  if (MinimumPasswordLength < 8) val = val + '\n\n' + "Minimale Kennwortlänge: " + MinimumPasswordLength;
  if (nodefaultadminowner != "1") val = val + '\n\n' + "Systemobjekte: Standardbesitzer für Objekte, die von\nMitgliedern der Administratorengruppe erstellt\nwerden: " + nodefaultadminowner;
  if (NoLMHash != "1") val = val + '\n\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte für\nnächste Kennwortänderung speichern: " + NoLMHash;
  if (NTLMMinClientSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit für\nNTLM-SSP-basierte Clients (einschließlich sicherer\nRPC-Clients: " + NTLMMinClientSec;
  if (NTLMMinServerSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit für\nNTLM-SSP-basierte Server (einschließlich sicherer\nRPC-Server): " + NTLMMinServerSec;
  if (NullSessionPipes != "Empty"){
    NullSessionPipes = split(NullSessionPipes, sep:'|', keep:0);
    for(i=0; i<max_index(NullSessionPipes); i++)
    {
      NullSessionPipesval += NullSessionPipes[i] + ';\n';
    }
    val = val + '\n\n' + "Netzwerkzugriff: Named Pipes, auf die anonym\nzugegriffen werden kann:\n" + NullSessionPipesval;
  }
  if (NullSessionShares != "Empty"){
    NullSessionShares = split(NullSessionShares, sep:'|', keep:0);
    for(i=0; i<max_index(NullSessionShares); i++)
    {
      NullSessionSharesval += NullSessionShares[i] + ';\n';
    }

    val = val + '\n\n' + "Netzwerkzugriff: Freigaben, auf die anonym zugegriffen\nwerden kann:\n" + NullSessionSharesval;
  }
  if (ObCaseInsensitive != "1") val = val + '\n\n' + "Systemobjekte: Groß-/Kleinschreibung für Nicht-\nWindows-Subsysteme ignorieren: " + ObCaseInsensitive;
  if (OverWritePolicyApp >< "None") val = val + '\n\n' + "Aufbewahrungsmethode des Anwendungsprotokolls: " + OverWritePolicyApp;
  else{
    if (OverWritePolicyApp[1] != "Bei Bedarf" && OverWritePolicyApp[1] != "WhenNeeded") val = val + '\n\n' + "Aufbewahrungsmethode des Anwendungsprotokolls: " + OverWritePolicyApp[1];
  }
  if (OverWritePolicyEvent >< "None") val = val + '\n\n' + "Aufbewahrungsmethode des Systemprotokolls: " + OverWritePolicyEvent;
  else{
    if (OverWritePolicyEvent[1] != "Bei Bedarf" && OverWritePolicyEvent[1] != "WhenNeeded") val = val + '\n\n' + "Aufbewahrungsmethode des Systemprotokolls: " + OverWritePolicyEvent[1];
  }
  if (OverWritePolicySec >< "None") val = val + '\n\n' + "Aufbewahrungsmethode des Sicherheitsprotokolls: " + OverWritePolicySec;
  else{
    if (OverWritePolicySec[1] != "Bei Bedarf" && OverWritePolicySec[1] != "WhenNeeded") val = val + '\n\n' + "Aufbewahrungsmethode des Sicherheitsprotokolls: " + OverWritePolicySec[1];
  }
  if (PasswordComplexity != "True") val = val + '\n\n' + "Kennwort muss Komplexitätsvoraussetzungen\nentsprechen: " + PasswordComplexity;
  if (passwordexpirywarning != "14") val = val + '\n\n' + "Interaktive Anmeldung: Anwender vor Ablauf des\nKennworts zum Ändern des Kennworts auffordern: " + passwordexpirywarning;
  if (PasswordHistorySize < 6) val = val + '\n\n' + "Kennwortchronik erzwingen: " + PasswordHistorySize;
  if (Policy != "1") val = val + '\n\n' + "Geräte: Verhalten bei der Installation von\nnichtsignierten Treibern: " + Policy;
  if (ProtectionMode != "1") val = val + '\n\n' + "Systemobjekte: Standardberechtigungen interner\nSystemobjekte (z. B. symbolischer Verknüpfungen)\nverstärken: " + ProtectionMode;
  if (RequireSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Kommunikation digital\nsignieren (immer): " + RequireSecuritySignatureSvr;
  if (RequireSecuritySignatureWs != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (immer): " + RequireSecuritySignatureWs;
  if (requiresignorseal != "1") val = val + '\n\n' + "Domänenmitglied: Daten des sicheren Kanals digital\nverschlüsseln oder signieren (immer): " + requiresignorseal;
  if (requirestrongkey != "1") val = val + '\n\n' + "Domänenmitglied: Starker Sitzungsschlüssel erforder-\nlich (Windows 2000 oder höher: " + requirestrongkey;
  if (ResetLockoutCount < 30) val = val + '\n\n' + "Zurücksetzungsdauer des Kontosperrungszählers: " + ResetLockoutCount;
  if (RestrictAnonymous != "1") val = val + '\n\n' + "Netzwerkzugriff: Anonyme Aufzählung von SAM-Konten und\nFreigaben nicht erlauben: " + RestrictAnonymous;
  if (RestrictAnonymousSAM != "1") val = val + '\n\n' + "Netzwerkzugriff: Anonyme Aufzählung von SAM-Konten\nnicht erlauben: " + RestrictAnonymousSAM;
  if (RestrictGuestAccessApp >< "None") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Anwendungsprotokoll\nverhindern: " + RestrictGuestAccessApp;
  else{
    if (RestrictGuestAccessApp[2] != "True") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Anwendungsprotokoll\nverhindern: " + RestrictGuestAccessApp[2];
  }
  if (RestrictGuestAccessEvent >< "None") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Systemprotokoll\nverhindern: " + RestrictGuestAccessEvent;
  else{
    if (RestrictGuestAccessEvent[2] != "True") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Systemprotokoll\nverhindern: " + RestrictGuestAccessEvent[2];
  }
  if (RestrictGuestAccessSec >< "None") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Sicherheitsprotokoll\nverhindern: " + RestrictGuestAccessSec;
  else{
    if (RestrictGuestAccessSec[2] != "True") val = val + '\n\n' + "Lokalen Gastkontozugriff auf Sicherheitsprotokoll\nverhindern: " + RestrictGuestAccessSec[2];
  }
  if (scremoveoption != "1") val = val + '\n\n' + "Interaktive Anmeldung: Verhalten beim Entfernen von\nSmartcards: " + scremoveoption;
  if (sealsecurechannel != "1") val = val + '\n\n' + "Domänenmitglied: Daten des sicheren Kanals digital\nverschlüsseln (wenn möglich): " + sealsecurechannel;
  if (securitylevel != "0") val = val + '\n\n' + "Wiederherstellungskonsole: Automatische administrative\nAnmeldungen zulassen: " + securitylevel;
  if (setcommand != "0") val = val + '\n\n' + "Wiederherstellungskonsole: Kopieren von Disketten und\nZugriff auf alle Laufwerke und alle Ordner zulassen: " + setcommand;
  if (ShutdownWithoutLogon != "0") val = val + '\n\n' + "Herunterfahren: Herunterfahren des Systems ohne\nAnmeldung zulassen: " + ShutdownWithoutLogon;
  if (signsecurechannel != "1") val = val + '\n\n' + "Domänenmitglied: Daten des sicheren Kanals digital\nsignieren (wenn möglich): " + signsecurechannel;
  if (undockwithoutlogon != "0") val = val + '\n\n' + "Geräte: Entfernen ohne vorherige Anmeldung erlauben: " + undockwithoutlogon;

  if(NoUpdateCheck == "0") val = val + '\n\n' + "Disable Periodic Check for Internet Explorer Software\nupdates: " + NoUpdateCheck;
  else if (NoUpdateCheck >< "None")  val = val + '\n\n' + "\nDisable Periodic Check for Internet Explorer Software\nupdates wurde nicht konfiguriert";
  if(PreventAutoRun == "0") val = val + '\n\n' + "Windows Messenger\Windows Messenger nicht automatisch\nstarten: " + PreventAutoRun;
  else if (PreventAutoRun >< "None")  val = val + '\n\n' + "Windows Messenger\Windows Messenger nicht automatisch\nstarten wurde nicht konfiguriert";
  if(EnabledNTPServer == "1") val = val + '\n\n' + "Windows-NTP-Server aktivieren: " + EnabledNTPServer;
  else if (EnabledNTPServer >< "None")  val = val + '\n\n' + "Windows-NTP-Server aktivieren wurde nicht konfiguriert";
  if(Headlines == "1") val = val + '\n\n' + "'Wussten Sie schon' -Inhalte im Hilfe- und\nSupportcenter deaktivieren: " + Headlines;
  else if (Headlines >< "None")  val = val + '\n\n' + "'Wussten Sie schon' -Inhalte im Hilfe- und\nSupportcenter deaktivieren wurde nicht konfiguriert";
  if(DisableWindowsUpdateAccess == "0") val = val + '\n\n' + "Zugriff auf alle Windows Update-Funktionen\ndeaktivieren: " + DisableWindowsUpdateAccess;
  else if (DisableWindowsUpdateAccess >< "None")  val = val + '\n\n' + "Zugriff auf alle Windows Update-Funktionen\ndeaktivieren wurde nicht konfiguriert";
  if(DontSearchWindowsUpdate == "0") val = val + '\n\n' + "Suche nach Gerätetreibern auf Windows Update\ndeaktivieren: " + DontSearchWindowsUpdate;
  else if (DontSearchWindowsUpdate >< "None")  val = val + '\n\n' + "Suche nach Gerätetreibern auf Windows Update\ndeaktivieren wurde nicht konfiguriert";
  if(NoRegistration == "0") val = val + '\n\n' + "Registrierung deaktivieren, wenn sich dir URL-\nVerbindung auf microsoft.com bezieht: " + NoRegistration;
  else if (NoRegistration >< "None")  val = val + '\n\n' + "Registrierung deaktivieren, wenn sich dir URL-\nVerbindung auf microsoft.com bezieht wurde nicht\nkonfiguriert";
  if(DisableRootAutoUpdate == "0") val = val + '\n\n' + "Automatischer Update von Stammzertifikaten\ndeaktivieren: " + DisableRootAutoUpdate;
  else if (DisableRootAutoUpdate >< "None")  val = val + '\n\n' + "Automatischer Update von Stammzertifikaten\ndeaktivieren wurde nicht konfiguriert";
  if(MicrosoftEventVwrDisableLinks == "0") val = val + '\n\n' + "Event.asp-Links der ereignisanzeige deaktivieren: " + MicrosoftEventVwrDisableLinks;
  else if (MicrosoftEventVwrDisableLinks >< "None")  val = val + '\n\n' + "Event.asp-Links der ereignisanzeige deaktivieren\nwurde nicht konfiguriert";
  if(NoInternetOpenWith == "0") val = val + '\n\n' + "Internet-Dateizuordnungsdienst deaktivieren: " + NoInternetOpenWith;
  else if (NoInternetOpenWith >< "None")  val = val + '\n\n' + "Internet-Dateizuordnungsdienst deaktivieren wurde\nnicht konfiguriert";
  if(DoReport == "1") val = val + '\n\n' + "Fehlerberichterstattung deaktivieren: " + DoReport;
  else if (DoReport >< "None")  val = val + '\n\n' + "Fehlerberichterstattung deaktivieren wurde\nnicht konfiguriert";

  desc = string('\nDie Sicherheitseinstellung stimmen nicht mit der Maß-\nnahme M4.224 Überein. Folgende Dienste und Ein-\nstellungen sind nicht wie gewünscht konfiguriert:\n' + val + '\nBitte überprüfen Sie weiterhin, ob folgende Domain-\npolicies richtig konfiguriert sind:\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\Abruf von\nMedieninformationen zu Musikdateien verhinden\n\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\\nBenutzeroberfläche\\Design festlegen und fixieren\n\nBenutzerkonfiguration\\Administrative Vorlagen\\\nWindows-Komponenten\\Windows Media Player\\Wiedergabe\\\nCodec-Download verhindern\n\nBitte prüfen Sie, ob der Einsatz von AppLocker sinnvoll sein kann.\n\nBitte beachten Sie auch das Kapitel -Restriktive\nBerechtigungsvergabe unter Windows XP- aus dem\nDokument -Konfigurations- und Sicherheitseinstellungen\nunter Windows XP-. Zu finden unter:\nhttps://www.bsi.bund.de/cae/servlet/contentblob/471594\n/publicationFile/31046/Hilfsmittel_Windows_XP_pdf.pdf');
}

set_kb_item(name:"GSHB/M4_244/result", value:result);
set_kb_item(name:"GSHB/M4_244/desc", value:desc);
set_kb_item(name:"GSHB/M4_244/name", value:name);


silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_244');

exit(0);
