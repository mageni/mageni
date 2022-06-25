###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_037.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.037
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
  script_oid("1.3.6.1.4.1.25623.1.0.94202");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04037.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_TELNET_Cisco_Voice.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern.

  Stand: 14. Ergänzungslieferung (14. EL).

  Hinweis:

  Cisco Geräte können nur über Telnet getestet werden, da sie SSH blowfish-cbc encryption nicht unterstützen.");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.037: Sperren bestimmter Absender-Faxnummern\n';

gshbm =  "IT-Grundschutz M4.037: ";

ciscovoice = get_kb_item("GSHB/Voice");
log = get_kb_item("GSHB/Voice/log");
translation = get_kb_item("GSHB/Voice/translation");

if (log == "no Telnet Port"){
  result = string("nicht zutreffend");
  desc = string('Beim Testen des Systems wurde kein Telnet-\nPort gefunden.');
}else if (ciscovoice == "no credentials set"){
  result = string("unvollständig");
  desc = string('Um diesen Test durchzuführen, muss ihn in den Vorein-\nstellungen unter: -IT-Grundschutz: List reject Rule on\nCisco Voip Devices over Telnet- ein Benutzername und\nPasswort eingetragen werden.');
}else if (ciscovoice == "Login Failed"){
  result = string("Fehler");
  desc = string('Es war nicht möglich sich am Zielsystem anzumelden.');
}else if (ciscovoice == "nocisco"){
  result = string("nicht zutreffend");
  desc = string('Das Ziel konnt nicht als Cisco-Gerät erkannt werden.');
}else if (ciscovoice == "novoice"){
  result = string("nicht zutreffend");
  desc = string('Das Ziel konnt als Cisco-Gerät erkannt werden.\nAllerdings konnte keine Voice-Funktion erkannt werden.');
}else if (translation == "noconfig"){
  result = string("nicht erfüllt");
  desc = string('Auf dem Cisco-Gerät wurde Voip Funktionalitäten\nentdeckt. Allerdings konnte keine -translation-rule-\nnacht dem Muster - rule .* reject .*- entdeckt werden.');
}else if (translation != "noconfig"){
  result = string("unvollständig");
  desc = string('Auf dem Cisco-Gerät wurde Voip Funktionalitäten ent-\ndeckt. Es wurden folgende -translation-rule- gefunden:\n' + translation +'\nBitte Prüfen Sie ob alle ggf. zu sperrenden\nAbsender-Faxnummern eingetragen sind.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}


set_kb_item(name:"GSHB/M4_037/result", value:result);
set_kb_item(name:"GSHB/M4_037/desc", value:desc);
set_kb_item(name:"GSHB/M4_037/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_037');

exit(0);
