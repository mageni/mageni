###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_284.nasl 11531 2018-09-21 18:50:24Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.284
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
  script_oid("1.3.6.1.4.1.25623.1.0.94224");
  script_version("$Revision: 11531 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 20:50:24 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04284.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_list_Services.nasl", "GSHB/GSHB_WMI_get_AdminUsers.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/nonSystemServices", "WMI/LocalWindowsAdminUsers", "WMI/WMI_OSVER", "WMI/WMI_OSNAME");
  script_tag(name:"summary", value:"IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.284: Umgang mit Diensten ab Windows Server 2003\n';

gshbm =  "IT-Grundschutz M4.284: ";
services = get_kb_item("WMI/nonSystemServices");
LocalAdminUsers = get_kb_item("WMI/LocalWindowsAdminUsers");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
log = get_kb_item("WMI/LocalWindowsAdminUsers/log");

if ("Name|StartName|State" >< services) services = split(services, sep:'\n', keep:0);
if (LocalAdminUsers >!< "None" && LocalAdminUsers >!< "error") LocalAdminUsers = split(LocalAdminUsers, sep:'|', keep:0);

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< services){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if("None" >< services){
  result = string("erf¸llt");
  desc = string("Auf dem System laufen alle Dienste gem‰ﬂ Maﬂnahme\nM4.284.");
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if("Name|StartName|State" >< services[0]){
    for(i=1; i<max_index(services); i++)
    {
       if("Name|StartName|State" >< services[i]){
          continue;
       }
       svinf = split(services[i], sep:"|", keep:0);
       if(svinf !=NULL)
       {
         svinf[1] = tolower(svinf[1]);
         if ('@' >< svinf[1] || (svinf[1] !~ "[.]\\.*" && svinf[1] =~ "[a-zA-Z0-9‰ƒˆ÷¸‹ﬂ-]{2,}\\.*"))
         {
         result = result + string("erf¸llt ");
         domservices = domservices + "Dienstname: " + svinf[0] + ',\nUseraccount: ' + svinf[1] + ', Dienststatus: ' + svinf[2] + ';\n';
         domdesc = string('\nAuf dem System laufen einige Dienste unter Dom‰nen-\naccounts. Bitte pr¸fen Sie folgende Dienste:\n');
         }

         else
         {
           for(u=0; u<max_index(LocalAdminUsers); u++)
             {
                 if(LocalAdminUsers[u] >< svinf[1])
                 {
                     result = result + string("nicht erf¸llt ");
                     servicesdesc = servicesdesc + "Dienstname: " + svinf[0] + ',\nUseraccount: ' + svinf[1] + ', Dienststatus: ' + svinf[2] + ';\n';
                 }
                 else
                 {
                     result = result + string("erf¸llt ");
                 }
              }
          }
       }
 }

  if ("nicht" >< result) result = string("nicht erf¸llt");
  else result = string("erf¸llt");
  if (servicesdesc) desc = string('\nFolgende Dienste entsprechen nicht der\nMaﬂnahme M4.284:\n') + servicesdesc + domdesc + domservices;
  else if (domservices) desc = domdesc + domservices;
  else if(!servicesdesc && !domservices) desc = string("Auf dem System laufen alle Dienste gem‰ﬂ\nMaﬂnahme M4.284");
}

set_kb_item(name:"GSHB/M4_284/result", value:result);
set_kb_item(name:"GSHB/M4_284/desc", value:desc);
set_kb_item(name:"GSHB/M4_284/name", value:name);


silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_284');

exit(0);
