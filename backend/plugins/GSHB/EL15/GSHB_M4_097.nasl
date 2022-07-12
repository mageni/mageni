###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_097.nasl 10628 2018-07-25 15:52:40Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.097
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
  script_oid("1.3.6.1.4.1.25623.1.0.94212");
  script_version("$Revision: 10628 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:52:40 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.097: Ein Dienst pro Server (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "secpod_open_tcp_ports.nasl");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04097.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.097: Ein Dienst pro Server.

  Stand: 14. Ergänzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("itg.inc");
include("wmi_svc.inc");
include("wmi_user.inc");
include("wmi_misc.inc");
include("misc_func.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.097: Ein Dienst pro Server\n';

gshbm =  "IT-Grundschutz M4.097: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
log = get_kb_item("WMI/WMI_OS/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

if(host && usrname && passwd){
 handle = wmi_connect(host:host, username:usrname, password:passwd);

 vhdsvc = wmi_svc_prop(handle:handle, svcName:"vhdsvc");
 nvspwmi = wmi_svc_prop(handle:handle, svcName:"nvspwmi");
 vmms = wmi_svc_prop(handle:handle, svcName:"vmms");

 if (vhdsvc){
   val = split(vhdsvc, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) vhdsvc_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])vhdsvc_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])vhdsvc_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])vhdsvc_state = val[i] - "State = ";
   }
 }
 if (nvspwmi){
   val = split(nvspwmi, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) nvspwmi_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])nvspwmi_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])nvspwmi_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])nvspwmi_state = val[i] - "State = ";
   }
 }
 if (vmms){
   val = split(vmms, "\n", keep:0);
   for(i=1; i<max_index(val); i++)
   {
     if ("Caption =" >< val[i]) vmms_cap = val[i] - "Caption = ";
     else if ("Started =" >< val[i])vmms_started = val[i] - "Started = ";
     else if ("StartMode =" >< val[i])vmms_startmode = val[i] - "StartMode = ";
     else if ("State =" >< val[i])vmms_state = val[i] - "State = ";
   }
 }
}

ports = get_all_tcp_ports_list();

portchecklist = make_list("21", "22", "23", "25", "42", "53", "66", "80", "102", "109", "110", "115", "118",
"119", "143", "270", "465", "515", "548", "554", "563", "992", "993", "995", "1270", "1433", "1434", "1723", "1755", "2393", "2394", "2725", "8080", "51515");

PORTTITEL = "
21 = File Transfer Protocol (FTP)
22 = Secure Shell (SSH) Protocol
23 = Telnet
25 = Simple Mail Transfer (SMTP)
42 = Windows Internet Name Service (WINS)
53 = DNS Server
66 = Oracle SQL*NET
80 = World Wide Web (HTTP)
102 = Microsoft Exchange MTA Stacks (X.400)
109 = Post Office Protocol - Version 2 (POP2)
110 = Post Office Protocol - Version 3 (POP3)
115 = Simple File Transfer Protocol (SFTP)
118 = SQL Services
119 = Network News Transfer Protocol (NNTP)
143 = Internet Message Access Protocol (IMAP4)
270 = Microsoft Operations Manager 2004
465 = Simple Mail Transfer over SSL (SMTPS)
515 = TCP/IP Print Server
548 = File Server for Macintosh
554 = Windows Media Services
563 = Network News Transfer Protocol over TLS/SSL (NNTPS)
992 = Telnet über TLS/SSL
993 = IMAP4 über TLS/SSL (IMAP4S)
995 = POP3 über TLS/SSL (POP3S)
1270 = MOM-Encrypted Microsoft Operations Manager 2000
1433 = Microsoft-SQL-Server
1434 = Microsoft-SQL-Monitor
1723 = Routing and Remote Access (PPTP)
1755 = Windows Media Services (MMS)
2393 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2394 = OLAP Services 7.0 SQL Server: Downlevel OLAP Client Support
2725 = SQL Analysis Services SQL 2000 Analysis Server
8080 = HTTP Alternative
51515 = MOM-Clear Microsoft Operations Manager 2000";

foreach port( ports ) {
  portlist = portlist + port + '|';
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba, es ist kein\nMicrosoft Windows System.");
}else if("none" >< OSVER){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(OSVER == '5.1' || (OSVER == '5.2' && OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER == '6.0' && OSTYPE == 1 ) || (OSVER == '6.1' && OSTYPE == 1 )){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Server.");
}
else
{
  checkport = split(portlist, sep:"|", keep:0);
  for (c=0; c<max_index(checkport); c++)
  {
    for (p=0; p<max_index(portchecklist); p++)
    {
      if (checkport[c] == portchecklist[p]){
        PORTNAME = egrep(pattern:'^' + checkport[c] + ' = ', string:PORTTITEL);
        PORTNAME = ereg_replace(pattern:'\n',replace:'', string:PORTNAME);
        RES = RES + "Port: " + PORTNAME + ';\n';
        CHECK = CHECK + 1;
      }
    }
  }
  if (vhdsvc_cap && nvspwmi_cap && vmms_cap){
    if (vhdsvc_state == "Running" &&  nvspwmi_state == "Running" &&  vmms_state == "Running"){
      if (RES)
      {
        result = string("nicht erfüllt");
        desc = string('Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n' + vmms_cap + '\nFolgende(r) Dienst läuft neben der Virtualisierungssoftware\nauf dem Server:\n' + RES);
      }
      else
      {
        result = string("erfüllt");
        desc = string('Auf dem Server wurde folgende Virtualisierungssoftware\ngefunden:\n'+ vmms_cap + '\nAuf dem Server laufenen keine weiteren zu überprüfenden\nDienste.');
      }
    }
  }
  else if (CHECK > 1)
  {
    result = string("nicht erfüllt");
    desc = string('Folgende Dienste laufen auf dem Server:\n') + RES;
    desc = desc + string ('\nPrüfen Sie bitte ob alle Dienste nötig sind.');
  }
  else if (RES)
  {
    result = string("erfüllt");
    desc = string('Folgender Dienst läuft alleine auf dem Server:\n') + RES;
  }
  else
  {
    result = string("erfüllt");
    desc = string('Auf dem Server laufen keine zu überprüfenden Dienste.') + RES;
  }
}

set_kb_item(name:"GSHB/M4_097/result", value:result);
set_kb_item(name:"GSHB/M4_097/desc", value:desc);
set_kb_item(name:"GSHB/M4_097/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_097');

exit(0);
