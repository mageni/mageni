# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109840");
  script_version("2019-04-17T10:11:48+0000");
  script_tag(name:"last_modification", value:"2019-04-17 10:11:48 +0000 (Wed, 17 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-08-27 13:03:22 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A7: Lokale Sicherheitsrichtlinien' beschreibt, dass und welche
Sicherheitsrichtlinien gesetzt werden sollten.");

  exit(0);
}

include("itg.inc");
include("host_details.inc");

if(!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Lokale Sicherheitsrichtlinien";
set_kb_item(name:"GSHB/SYS.2.2.3.A7/title", value:title);

host_cpe = best_os_cpe();
if("microsoft:windows_10" >< host_cpe) {
  desc = "Diese Vorgabe muss manuell ueberprueft werden.";
  result = "Diese Vorgabe muss manuell ueberprueft werden.";
} else {
  result = "nicht zutreffend";
  desc = "Host ist kein Microsoft Windows 10 System.";
}

set_kb_item(name:"GSHB/SYS.2.2.3.A7/result", value:result);
set_kb_item(name:"GSHB/SYS.2.2.3.A7/desc", value:desc);

silent = get_kb_item("GSHB/silence");
if(!silent)
  itg_report(title:title, status:result, details:desc);

exit(0);