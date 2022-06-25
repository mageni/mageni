###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_147.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.147
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
  script_oid("1.3.6.1.4.1.25623.1.0.95076");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05147.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.147: Absicherung der Kommunikation mit Verzeichnisdiensten\n';

gshbm =  "IT-Grundschutz M5.147: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
log = get_kb_item("WMI/WMI_OS/log");
PORT389 = get_kb_list("Ports/tcp/389");
PORT636 = get_kb_list("Ports/tcp/636");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
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
  if (PORT389)
  {
    if (PORT636)
    {
      result = string("erf¸llt");
      desc = string('LDAP ¸ber SSL/TLS ist aktiviert.');
    }
    else
    {
      result = string("nicht erf¸llt");
      desc = string('LDAP ¸ber SSL/TLS ist nicht aktiviert.');
    }
  }
  else
  {
    if (PORT636)
    {
      result = string("erf¸llt");
      desc = string('LDAP ist nur ¸ber SSL/TLS aktiviert.');
    }
    else
    {
      result = string("nicht zutreffen");
      desc = string('LDAP ist auf dem Server nicht installiert.');
    }
  }
}

set_kb_item(name:"GSHB/M5_147/result", value:result);
set_kb_item(name:"GSHB/M5_147/desc", value:desc);
set_kb_item(name:"GSHB/M5_147/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_147');

exit(0);
