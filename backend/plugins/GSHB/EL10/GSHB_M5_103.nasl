###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_103.nasl 10129 2018-06-08 08:13:23Z emoss $
#
# IT-Grundschutz, 10. EL, Massnahme 5.103
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
  script_oid("1.3.6.1.4.1.25623.1.0.95103");
  script_version("$Revision: 10129 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 10:13:23 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Tools/Present/wmi", "Compliance/Launch/GSHB-10");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_IIS_OpenPorts.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/IISandPorts", "WMI/Shares", "WMI/AUTOSHARE", "WMI/IPC");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05103.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstuetzt. Er wurde zudem in neueren
  EL gestrichen.

  Diese Pruefung bezieht sich auf die 10. Ergaenzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Massnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergaenzungslieferung bezieht. Titel und Inhalt koennen sich bei einer
  Aktualisierung aendern, allerdings nicht die Kernthematik.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

exit(66);
