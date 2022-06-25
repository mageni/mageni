##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_Kompendium.nasl 10624 2018-07-25 15:18:47Z cfischer $
#
# IT-Grundschutz Kompendium
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
  script_oid("1.3.6.1.4.1.25623.1.0.109040");
  script_version("$Revision: 10624 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:18:47 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-01-29 10:14:11 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, Kompendium");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Compliance");
  script_add_preference(name:"Berichtformat", type:"radio", value:"Text;Tabellarisch;Text und Tabellarisch");
  script_mandatory_keys("GSHB/silence", "Compliance/Launch/GSHB-ITG");
  script_dependencies("compliance_tests.nasl", "GSHB/GSHB_SYS.1.2.2.nasl", "GSHB/GSHB_SYS.1.3.nasl", "GSHB/GSHB_SYS.2.2.2.nasl", "GSHB/GSHB_SYS.2.2.3.nasl", "GSHB/GSHB_SYS.2.3.nasl");
  script_tag(name:"summary", value:"Zusammenfassung von Tests gemäß IT-Grundschutz Kompendium.

Diese Routinen prüfen sämtliche Massnahmen des
IT-Grundschutz Kompendiums des Bundesamts fuer Sicherheit
in der Informationstechnik (BSI) auf den
Zielsystemen soweit die Maßnahmen auf automatisierte
Weise abgeprüft werden können.");

  exit(0);
}

include("GSHB/GSHB_mtitle.inc");
include("GSHB/GSHB_depend.inc");

level = get_kb_item("GSHB/level");

report = 'Prüfergebnisse gemäß IT-Grundschutz Kompendium:\n\n\n';
log = string('');

foreach m (mtitle) {
  m = split(m, sep:"|", keep:FALSE);
  m_num = m[0];
  m_title = m[1];
  m_level = m[2];

  if ((level == 'Basis' && m_level == 'Standard') ||
      (level == 'Basis' && m_level == 'Kern')){
    continue;
  }
  if (level == "Standard" && m_level == 'Kern'){
    continue;
  }

  result = get_kb_item("GSHB/" + m_num + "/result");
  desc = get_kb_item("GSHB/" + m_num + "/desc");

  if (!result){
    if (m_num >< depend){
      result = 'Diese Vorgabe muss manuell überprüft werden.';
    }else{
      result = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
    }
  }

  if (!desc) {
    if (m_num >< depend){
      desc = 'Diese Vorgabe muss manuell überprüft werden.';
    }else{
      desc = 'Prüfroutine für diese Maßnahme ist nicht verfügbar.';
    }
    read_desc = desc;
  }else{
    read_desc = ereg_replace(pattern:'\n',replace:'\\n', string:desc);
    read_desc = ereg_replace(pattern:'\\\\n',replace:'\\n                ', string:read_desc);
  }

  report = report + ' \n' + m_num + " " + m_title + '\n' + 'Ergebnis:       ' + result +
           '\nDetails:        ' + read_desc + '\n_______________________________________________________________________________\n';

  if (result >< 'error') result = 'ERR';
  else if (result >< 'Fehler') result = 'ERR';
  else if (result >< 'erfüllt') result = 'OK';
  else if (result >< 'erfuellt') result = 'OK';
  else if (result >< 'nicht zutreffend') result = 'NS';
  else if (result >< 'nicht erfuellt') result = 'FAIL';
  else if (result >< 'nicht erfüllt') result = 'FAIL';
  else if (result >< 'unvollstaendig') result = 'NC';
  else if (result >< 'Diese Vorgabe muss manuell überprüft werden.') result = 'NA';
  else if (result >< 'Prüfroutine für diese Maßnahme ist nicht verfügbar.') result = 'NI';
  ip = get_host_ip ();
  log_desc = ereg_replace(pattern:'\n',replace:' ', string:desc);
  log_desc = ereg_replace(pattern:'\\\\n',replace:' ', string:log_desc);

  log = log + string('"' + ip + '"|"' + m_num + '"|"' + result + '"|"' + log_desc + '"') + '\n';

}

format = script_get_preference("Berichtformat");
if (format == "Text" || format == "Text und Tabellarisch") {
  security_message(port:0, proto: "IT-Grundschutz", data:report);
}
if (format == "Tabellarisch" || format == "Text und Tabellarisch") {
  log_message(port:0, proto: "IT-Grundschutz-T", data:log);
}

exit(0);
