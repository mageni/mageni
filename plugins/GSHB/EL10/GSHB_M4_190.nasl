###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_190.nasl 14124 2019-03-13 07:14:43Z cfischer $
#
# IT-Grundschutz, 10. EL, Maßnahme 4.190
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
  script_oid("1.3.6.1.4.1.25623.1.0.94190");
  script_version("$Revision: 14124 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.190: Entfernen der RDS-Unterstützung des IIS (Windows)");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04190.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-10");
  script_mandatory_keys("Compliance/Launch/GSHB-10", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_IIS_RDS.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/RDSServer.DataFactory", "WMI/AdvancedDataFactory", "WMI/VbBusObj.VbBusObjCls");
  script_tag(name:"summary", value:"IT-Grundschutz M4.190: Entfernen der RDS-Unterstützung des IIS (Windows)

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde zudem in neueren
  EL gestrichen.

  Diese Prüfung bezieht sich auf die 10. Ergänzungslieferung (10. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Maßnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergänzungslieferung bezieht. Titel und Inhalt können sich bei einer
  Aktualisierung ändern, allerdings nicht die Kernthematik.");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
