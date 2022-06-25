##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_328.nasl 10396 2018-07-04 09:13:46Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.328
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
  script_oid("1.3.6.1.4.1.25623.1.0.94236");
  script_version("$Revision: 10396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("GSHB/GSHB_SSH_Samba.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04328.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.328: Sichere Grundkonfiguration eines Samba-Servers\n';

samba = kb_smb_is_samba();
global = get_kb_item("GSHB/SAMBA/global");
netlogon = get_kb_item("GSHB/SAMBA/netlogon");
smbpasswd = get_kb_item("GSHB/SAMBA/smbpasswd");
secretstdb = get_kb_item("GSHB/SAMBA/secretstdb");
log = get_kb_item("GSHB/SAMBA/log");

global = tolower(global);
netlogon = tolower(netlogon);

if(global != "none" && global != "novalentrys"){
  Lst = split(global,keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("security" >< Lst[i]) security = Lst[i];
    if ("ntlm auth" >< Lst[i]) ntlmauth = Lst[i];
    if ("valid users" >< Lst[i]) validusers = Lst[i];
    if ("hosts allow" >< Lst[i]) hostsallow = Lst[i];
    if ("hosts deny" >< Lst[i]) hostsdeny = Lst[i];
    if ("interfaces" >< Lst[i]) interfaces = Lst[i];
    if ("bind interfaces only" >< Lst[i]) bindinterfacesonly = Lst[i];
    if ("follow symlinks" >< Lst[i]) followsymlinks = Lst[i];
    if ("wide links" >< Lst[i]) widelinks = Lst[i];
    if ("passdb backend" >< Lst[i]) passdbbackend = Lst[i];
  }
}

if(netlogon != "none" && netlogon != "novalentrys"){
  Lst = split(netlogon,keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("read only =" >< Lst[i]) readonly = Lst[i];
  }
}

if (!security) security = "false";
if (!ntlmauth) ntlmauth = "false";
if (!validusers) validusers = "false";
if (!hostsallow) hostsallow = "false";
if (!hostsdeny) hostsdeny = "false";
if (!interfaces) interfaces = "false";
if (!bindinterfacesonly) bindinterfacesonly = "false";
if (!followsymlinks) followsymlinks = "false";
if (!widelinks) widelinks = "false";
if (!readonly) readonly = "false";
if (!passdbbackend) passdbbackend = "false";


if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein Samba-Dateiserver.');
}else if(global == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(global == "none" || global == "novalentrys"){
  result = string("Fehler");
  desc = string('Auf dem System wurde keine Konfiguration f¸r einen\nSamba-Dateiserver gefunden.');
}else{
  if ("share" >< security || "server" >< security || security == "false"){
    result = string("nicht erf¸llt");
    if("share" >< security)desc = string('Der Sicherheitsmodus -share- darf nicht verwendet\nwerden.');
    else if("server" >< security)desc = string('Der Sicherheitsmodus -server- darf nicht verwendet\nwerden.');
    else if (security == "false")desc = string('Es wurde kein Sicherheitsmodus konfiguriert.');
  }else{
    if ((hostsallow == "false" && hostsdeny == "false") || hostsallow == "false"){
      hostsallow_res = "ne";
      hostsallow_desc = '- Samba sollte so konfiguriert werden, dass\nVerbindungen nur von als sicher geltenden Hosts und\nNetzen entgegengenommen werden.\n';
    }
    if (validusers == "false"){
      validusers_res = "ne";
      validusers_desc = '\n- Generell sollte nur ausgew‰hlten Benutzern und\nBenutzergruppen erlaubt werden, sich mit dem Samba-\nDienst verbinden zu d¸rfen.\nDer Zugriff sollte daher\nin der Konfigurationsdatei smb.conf mit der Option\n-valid users- beschr‰nkt werden.\n';
    }
    if (interfaces == "false" || "yes" >!< bindinterfacesonly){
      interfaces_res = "ne";
      interfaces_desc = '\n- Standardm‰ﬂig bindet sich Samba an alle verf¸gbaren\nNetzadressen des Systems.\nSamba sollte so konfigu-\nriert werden, dass es sich nur an als sicher geltende\nNetzadressen bindet.\n';
    }
    if((netlogon != "false" && netlogon != "novalentrys") &&  "yes" >!< readonly){
      netlogon_res = "ne";
      netlogon_desc = '\n- Wird eine [netlogon] Freigabe konfiguriert, so\nsollte der freigabespezifischen Parameter\n-read only = yes- gesetzt werden.\n';
    }
    if (passdbbackend != "false"){
      if ("tdbsam" >< passdbbackend){
        if (secretstdb !~ "-rw-------.*"){
          passdbbackend_res = "ne";
          passdbbackend_desc = '\n- Es muss sichergestellt werden, dass ein Benutzer\nkeine Hash-Werte aus dem Backend auslesen kann. Bei\nden Backends tdbsam sollte daher nur der Benutzer\n"root" Lese- und Schreibzugriff auf die Datei haben,\nin denen die Benutzerinformationen abgelegt werden.\n';
        }
      }
      else if ("smbpasswd" >< passdbbackend){
        if (smbpasswd !~ "-rw-------.*"){
          passdbbackend_res = "ne";
          passdbbackend_desc = '\n- Es muss sichergestellt werden, dass ein Benutzer\nkeine Hash-Werte aus dem Backend auslesen kann. Bei\nden Backends smbpasswd sollte daher nur der Benutzer\n"root" Lese- und Schreibzugriff auf die Datei haben,\nin denen die Benutzerinformationen abgelegt werden.\n';
        }else{
          passdbbackend_res = "ne";
          passdbbackend_desc = '\n- Es sollte von der Verwendung des smbpasswd-Backends\nabgesehen werden. Es muss sichergestellt werden, dass\nein Benutzer keine Hash-Werte aus dem Backend auslesen\nkann.\nBei den Backends smbpasswd sollte daher nur der\nBenutzer "root" Lese- und Schreibzugriff auf die Datei\nhaben,\nin denen die Benutzerinformationen abgelegt\nwerden.\n';
        }
      }
    }
    if ("no" >!< followsymlinks && "no" >!< widelinks){
      links_res = "ne";
      links_desc = string('\n- Schreiben die Sicherheitsrichtlinien vor, dass\nBenutzer keinen Zugriff auf Informationen\nauﬂerhalb\nder Freigaben haben d¸rfen, so wird empfohlen\n-wide links = no- zu setzen.\n');
    }
    if ("domain" >< security || "ads" >< security){
      if("no" >!< ntlmauth || ntlmauth == "false"){
        ntlmauth_res = "ne";
        ntlmauth_desc = string('\n- Damit Samba nur NTLMv2 einsetzt, muss der Parameter\n-ntlm auth = no- in der Konfigurationsdatei smb.conf\ngesetzt werden.\n');
      }
    }
    if (hostsallow_res == "ne" || validusers_res == "ne" || interfaces_res == "ne" || netlogon_res == "ne" || passdbbackend_res == "ne" || ntlmauth == "ne"){
      result = string("nicht erf¸llt");
      desc = hostsallow_desc + validusers_desc + interfaces_desc + netlogon_desc + ntlmauth_desc + passdbbackend_desc + links_desc;
    }else{
      result = string("erf¸llt");
      desc = string('Die Grundkonfiguration Ihres Samba-Servers entspricht\nder Maﬂnahme 4.328.');
      if (links_res == "ne") desc += string('\nBeachten Sie aber:\n' + links_desc);
    }
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_328/result", value:result);
set_kb_item(name:"GSHB/M4_328/desc", value:desc);
set_kb_item(name:"GSHB/M4_328/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_328');

exit(0);
