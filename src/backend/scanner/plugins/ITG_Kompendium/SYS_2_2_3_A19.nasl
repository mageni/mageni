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
  script_oid("1.3.6.1.4.1.25623.1.0.109981");
  script_version("2019-12-06T11:01:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 11:01:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A19");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"gsf/Policy/Windows10/UserRightsAssignment/win10_access_computer_from_network.nasl",
"gsf/Policy/Windows10/UserRightsAssignment/win10_allow_logon_remote_desktop_services.nasl",
"gsf/Policy/Windows10/UserRightsAssignment/win10_deny_logon_remote_desktop_service.nasl",
"gsf/Policy/WindowsGeneral/SystemServices/win_rdesktop_configuration.nasl",
"gsf/Policy/WindowsGeneral/SystemServices/win_rdesktop_services.nasl",
"gsf/Policy/WindowsGeneral/SystemServices/win_rdesktop_umrdpservice.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_com_redirection.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_drive_redirection.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_lpt_redirection.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_pnp_redirection.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_idle.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_disconnect_limit.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_temp_dirs.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/win_rdhost_temp_session.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A19: Verwendung des Fernzugriffs per RDP' beschreibt, dass die Verwendung
von RDP konfiguriert werden sollte.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Verwendung des Fernzugriffs per RDP";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services,
Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services,
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Remote Desktop Configuration,
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Remote Desktop Services,
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Remote Desktop Services UserMode Port Redirector,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow COM port redirection,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow drive redirection,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow LPT port redirection,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\Do not allow supported Plug and Play device redirection,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for active but idle Remote Desktop Services sessions,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Session Time Limits\Set time limit for disconnected sessions,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not delete temp folders upon exit,
Computer Configuration\Policies\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders\Do not use temporary folders per session";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109113",
"1.3.6.1.4.1.25623.1.0.109117",
"1.3.6.1.4.1.25623.1.0.109131",
"1.3.6.1.4.1.25623.1.0.109270",
"1.3.6.1.4.1.25623.1.0.109271",
"1.3.6.1.4.1.25623.1.0.109272",
"1.3.6.1.4.1.25623.1.0.109465",
"1.3.6.1.4.1.25623.1.0.109466",
"1.3.6.1.4.1.25623.1.0.109467",
"1.3.6.1.4.1.25623.1.0.109468",
"1.3.6.1.4.1.25623.1.0.109472",
"1.3.6.1.4.1.25623.1.0.109473",
"1.3.6.1.4.1.25623.1.0.109474",
"1.3.6.1.4.1.25623.1.0.109475");

# Create and set kb entries for GSHB_Kompendium VT
if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
} else {
  results_list = itg_get_policy_control_result(oid_list:oid_list);
  result = itg_translate_result(compliant:results_list["compliant"]);
}
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A19");

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);
itg_report(report:report);

exit(0);