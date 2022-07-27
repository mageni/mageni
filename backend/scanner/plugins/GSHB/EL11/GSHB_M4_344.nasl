###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_344.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 11. EL, Maßnahme 4.344
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
  script_oid("1.3.6.1.4.1.25623.1.0.894344");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-01-22 13:48:09 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.344: Überwachung eines Windows Vista Systems (Windows)");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04344.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_NtpServer.nasl", "GSHB/GSHB_WMI_EventLogPolSet.nasl", "GSHB/GSHB_WMI_PolSecSet.nasl");
  script_require_keys("WMI/ELCP/GENERAL");

  script_tag(name:"summary", value:"IT-Grundschutz M4.344: Überwachung eines Windows Vista Systems.

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94248

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  *********************************ACHTUNG**************************************

  Diese Prüfung weicht von der offiziellen Ergänzungslieferung 11 ab.

  Die Aufgeführen Pfade und Tabellen sind Teilweise falsch:

  Der Pfad lautet (ab Vista) nicht mehr
  'Computerkonfiguration   Windows-Einstellungen   Sicherheitseinstellungen
  Lokale Richtlinien   Ereignisprotokoll'

  sondern

  'Computerkonfiguration   Administrative Vorlagen   Windows-Komponenten
  Ereignisprotokolldienst   <Protokoll>'

  Die Verweise in der Tabelle auf den 'Lokalen Gastkontogriff...' treffen für
  Windows Vista nicht mehr zu.

  Dieser Fehler wurde von der IT-Grundschutz Koordinierungsstelle
  bestätigt und wird mit der nächsten Ergänzungslieferung korrigiert.

  Hinweis:

  Die Maßnahme ist in EL11 technisch fehlerhaft.
  Der Test führt abweichend von der Maßnahme den korrekten Test aus.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
