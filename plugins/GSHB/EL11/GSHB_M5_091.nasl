###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_091.nasl 10625 2018-07-25 15:24:35Z cfischer $
#
# IT-Grundschutz, 11. EL, Maßnahme 5.091
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
  script_oid("1.3.6.1.4.1.25623.1.0.895091");
  script_version("$Revision: 10625 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:24:35 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-01-26 13:42:28 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.091: Einsatz von Personal Firewalls für Internet-PCs");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05091.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-11");
  script_mandatory_keys("Compliance/Launch/GSHB-11", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_WinFirewallStat.nasl", "GSHB/GSHB_SSH_iptables.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M5.091: Einsatz von Personal Firewalls für Internet-PCs.

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.95070

  Diese Prüfung bezieht sich auf die 11. Ergänzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.

  Hinweis:

  Getestet wird auf die Microsoft Windows Firewall. Für Vista und Windows 7
  auf jegliche Firewall die sich systemkonform installiert.
  Auf Linux, soweit möglich, anzeige der iptables Regeln.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
