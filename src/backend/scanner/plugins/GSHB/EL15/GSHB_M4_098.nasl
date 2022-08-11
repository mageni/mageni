###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_098.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.098
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
  script_oid("1.3.6.1.4.1.25623.1.0.94213");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschränken");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04098.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_WinFirewallStat.nasl");
  script_require_keys("WMI/WinFirewall");
  script_tag(name:"summary", value:"IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschränken.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Getestet wird auf die Microsoft Windows Firewall. Für Vista und Windows 7
  auf jegliche Firewall die sich systemkonform installiert.");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschränken\n';

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
Domainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
SMBOSVER = get_kb_item("SMB/WindowsVersion");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
FW = get_kb_item("WMI/WinFirewall");
IPFilter = get_kb_item("WMI/WinFirewall/IPFilter");
STD = get_kb_item("WMI/WinFirewall/STD");
DOM = get_kb_item("WMI/WinFirewall/DOM");
PUB = get_kb_item("WMI/WinFirewall/PUB");
Firewall_Name = get_kb_item("WMI/WinFirewall/Firewall_Name");
Firewall_State = get_kb_item("WMI/WinFirewall/Firewall_State");
log = get_kb_item("WMI/WinFirewall/log");

gshbm = "GSHB Maßnahme 4.098: ";


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba,\nes ist kein Microsoft Windows System.");
}else if(FW == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if (OSVER < '5.1'){
  result = string("unvollständig");
  desc = string("Das Windows 2000 System kann nicht geprüft werden.");
}else if (FW == "on"){
  result = string("erfüllt");
  desc = string("Auf dem System ist eine Personal Firewall aktiviert.");
}else if(OSVER == "5.2" && OSTYPE != "none" && OSTYPE > 1){

  IPFilter = split(IPFilter, sep:'\n', keep:0);
  IPFilter = split(IPFilter[1], sep:'|', keep:0);
  NWCard = IPFilter[0];
  IPFilter = IPFilter[2];

  if (IPFilter == "True"){
    result = string("erfüllt");
    desc = string("Auf dem System ist die Windows Firewall für folgende\nNetzwerkkarte aktiviert:\n" + NWCard);
    }else{
    result = string("nicht erfüllt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
    }
}else if(Firewall_State != "none" && Firewall_State != "inapplicable"){

  Firewall_Name = split(Firewall_Name, sep:'\n', keep:0);
  Firewall_Name = split(Firewall_Name[1], sep:'|', keep:0);
  Firewall_Name = Firewall_Name[0];

  Firewall_State = split(Firewall_State, sep:'\n', keep:0);
  Firewall_State = split(Firewall_State[1], sep:'|', keep:0);
  Firewall_State = Firewall_State[1];

  if(Firewall_State == "266256"){
    result = string("erfüllt");
    desc = string("Auf dem System ist folgende Firewall Software\naktiviert: " + Firewall_Name);
  }else if(Firewall_State == "262160" && Domainrole == "0" && STD =="1"){
    result = string("erfüllt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "0" && STD =="off"){
    result = string("nicht erfüllt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "1" && DOM =="1"){
    result = string("erfüllt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }else if(Firewall_State == "262160" && Domainrole == "1" && DOM =="off"){
    result = string("nicht erfüllt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }
}else if(Domainrole == "0" || Domainrole == "2"){
  if (STD == "off" && PUB == "off"){
    result = string("nicht erfüllt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if (STD == "1" && PUB == "1"){
    result = string("erfüllt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }else if (STD == "off" && PUB == "1"){
    result = string("unvollständig");
    desc = string("Auf dem System ist die Windows Firewall nur für\n-Öffentliche Netzwerke- aktiviert. Sie sollten die\nWindows Firewall für sämtliche Netzwerke aktivieren.");
  }else if (STD == "1" && PUB == "off"){
    result = string("unvollständig");
    desc = string("Auf dem System ist die Windows Firewall nur für\n-Private- / Arbeitsplatz Netzwerke- aktiviert. Sie\nsollten die Windows Firewall für sämtliche Netzwerke\naktivieren.");
  }
}else if(Domainrole == "1" || Domainrole > 2 ){
  if (DOM == "off"){
    result = string("nicht erfüllt");
    desc = string("Auf dem System ist keine Personal Firewall aktiviert.");
  }else if (DOM == "1"){
    result = string("erfüllt");
    desc = string("Auf dem System ist die Windows Firewall aktiviert.");
  }
}

set_kb_item(name:"GSHB/M4_098/result", value:result);
set_kb_item(name:"GSHB/M4_098/desc", value:desc);
set_kb_item(name:"GSHB/M4_098/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_098');

exit(0);
