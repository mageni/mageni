# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109978");
  script_version("2019-12-06T11:01:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 11:01:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A16");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"gsf/Policy/WindowsGeneral/System/win_access_store.nasl",
"gsf/Policy/Windows10/WindowsComponents/win_block_hosted_app_access_winrt.nasl",
"gsf/Policy/Windows10/WindowsComponents/win_store_no_apps.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_store_app.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A16: Anbindung von Windows 10 an den Microsoft-Store' beschreibt, dass der
Microsoft-Store deaktiviert werden sollte.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Anbindung von Windows 10 an den Microsoft-Store";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off access to the Store,
Computer Configuration\Policies\Administrative Templates\Windows Components\App runtime\Block launching Windows Store apps with Windows Runtime API access from hosted content.,
Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Disable all apps from Windows Store,
Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Turn off the Store application";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109353",
"1.3.6.1.4.1.25623.1.0.109369",
"1.3.6.1.4.1.25623.1.0.109481",
"1.3.6.1.4.1.25623.1.0.109484");

# Create and set kb entries for GSHB_Kompendium VT
if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
} else {
  results_list = itg_get_policy_control_result(oid_list:oid_list);
  result = itg_translate_result(compliant:results_list["compliant"]);
}
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A16");

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);
itg_report(report:report);

exit(0);