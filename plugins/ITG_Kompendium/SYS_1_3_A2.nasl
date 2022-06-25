# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_version("2021-03-12T13:45:12+0000");
  script_oid("1.3.6.1.4.1.25623.1.0.150582");
  script_tag(name:"last_modification", value:"2021-03-12 13:45:12 +0000 (Fri, 12 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-10 09:31:46 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");

  script_name("SYS.1.3.A2");

  script_category(ACT_GATHER_INFO);
  script_family("IT-Grundschutz");
  script_dependencies("os_detection.nasl", "compliance_tests.nasl",
    "Policy/Linux/SystemMaintenance/no_duplicate_username.nasl",
    "Policy/Linux/SystemMaintenance/groups_passwd_in_group.nasl",
    "Policy/Linux/SystemMaintenance/no_duplicate_gids.nasl",
    "Policy/Linux/SystemMaintenance/no_duplicate_uids.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_1_3_Server_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=3");
  script_tag(name:"summary", value:"Jeder Login-Name, jede Benutzer-ID (User-ID, UID) und jede
Gruppen-ID (GID) DARF NUR einmal vorkommen. Jeder Benutzer MUSS Mitglied mindestens einer Gruppe
sein. Jede in der Datei /etc/passwd vorkommende GID MUSS in der Datei /etc/group definiert sein.
Jede Gruppe SOLLTE nur die Benutzer enthalten, die unbedingt notwendig sind. Bei vernetzten Systemen
MUSS ausserdem darauf geachtet werden, dass die Vergabe von Benutzer- und Gruppennamen, UID und GID
im Systemverbund konsistent erfolgt, wenn beim systemuebergreifenden Zugriff die Moeglichkeit besteht,
dass gleiche UIDs bzw. GIDs auf den Systemen unterschiedlichen Benutzer- bzw. Gruppennamen zugeordnet
werden koennten.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Basis"))
  exit(0);

title = "Sorgfaeltige Vergabe von IDs";

desc = "Folgende Einstellungen werde getestet:
Keine doppelten Usernamen, UIDs oder GIDs.
Alle Gruppen in /etc/passwd existieren in /etc/groups.";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109832",
  "1.3.6.1.4.1.25623.1.0.109833",
  "1.3.6.1.4.1.25623.1.0.109831",
  "1.3.6.1.4.1.25623.1.0.109834");

if (host_runs("linux") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.3.A2");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.3.A2");
itg_report(report:report);

exit(0);