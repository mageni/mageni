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
  script_oid("1.3.6.1.4.1.25623.1.0.109968");
  script_version("2019-12-06T11:01:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 11:01:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A4");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"gsf/Policy/WindowsGeneral/SystemServices/win_problem_reports_control_panel.nasl",
"gsf/Policy/WindowsGeneral/SystemServices/win_error_reporting_service.nasl",
"gsf/Policy/WindowsGeneral/System/win_messenger_cust_experience.nasl",
"gsf/Policy/WindowsGeneral/System/win_cust_experience.nasl",
"gsf/Policy/WindowsGeneral/System/win_error_reporting.nasl",
"gsf/Policy/WindowsGeneral/System/win_query_remote_server.nasl",
"gsf/Policy/WindowsGeneral/System/win_perf_track.nasl",
"gsf/Policy/WindowsGeneral/System/win_advertising_id.nasl",
"gsf/Policy/Windows10/WindowsComponents/win10_allowtelemetry.nasl",
"gsf/Policy/Windows10/WindowsComponents/win_enterprise_auth_proxy.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_kms_client_online_avs.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_watson_events.nasl",
"gsf/Policy/Windows10/UserTemplates/win_dignostic_data_experience.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Basis-Anforderung 'A4: Telemetrie und Datenschutzeinstellungen' beschreibt,
dass Telemetriedienste soweit moeglich abgeschaltet werden muessen.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Basis"))
  exit(0);

title = "Telemetrie und Datenschutzeinstellungen";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Problem Reports and Solutions Control Panel Support,
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Windows Error Reporting Service,
Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off the Windows Messenger Customer Experience Improvement Program,
Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Customer Experience Improvement Program,
Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Error Reporting,
Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider,
Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Windows Performance PerfTrack\Enable/Disable PerfTrack,
Computer Configuration\Policies\Administrative Templates\System\User Profiles\Turn off the advertising ID,
Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Telemetry,
Computer Configuration\Policies\Administrative Templates\Windows Components\Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service,
Computer Configuration\Policies\Administrative Templates\Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation,
Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender\Reporting\Configure Watson events,
User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109268",
"1.3.6.1.4.1.25623.1.0.109282",
"1.3.6.1.4.1.25623.1.0.109364",
"1.3.6.1.4.1.25623.1.0.109365",
"1.3.6.1.4.1.25623.1.0.109366",
"1.3.6.1.4.1.25623.1.0.109546",
"1.3.6.1.4.1.25623.1.0.109547",
"1.3.6.1.4.1.25623.1.0.109548",
"1.3.6.1.4.1.25623.1.0.109094",
"1.3.6.1.4.1.25623.1.0.109434",
"1.3.6.1.4.1.25623.1.0.109480",
"1.3.6.1.4.1.25623.1.0.109485",
"1.3.6.1.4.1.25623.1.0.109522");

# Create and set kb entries for GSHB_Kompendium VT
if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
} else {
  results_list = itg_get_policy_control_result(oid_list:oid_list);
  result = itg_translate_result(compliant:results_list["compliant"]);
}
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A4");

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);
itg_report(report:report);

exit(0);