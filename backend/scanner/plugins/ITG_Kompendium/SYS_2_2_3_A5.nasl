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
  script_oid("1.3.6.1.4.1.25623.1.0.109969");
  script_version("2019-12-06T11:01:56+0000");
  script_tag(name:"last_modification", value:"2019-12-06 11:01:56 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A5");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_state.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_inbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_outbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_notification.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_logging_name.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_logging_size.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_dropped_packets.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_domain_successful_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_state.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_inbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_outbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_notification.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_logging_name.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_logging_size.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_dropped_packets.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_private_successful_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_state.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_inbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_outbound_connections.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_notification.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_advsec_publicfw_localfwrules.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_advsec_publicfw_localconsecrules.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_logging_name.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_logging_size.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_dropped_packets.nasl",
"gsf/Policy/WindowsGeneral/FirewallGPO/win_fw_public_successful_connections.nasl",
"gsf/Policy/WindowsGeneral/WindowsComponents/turn_off_game_updates.nasl",
"gsf/Policy/WindowsGeneral/UserTemplates/win_avprograms_attachments.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Basis-Anforderung 'A5: Schutz vor Schadsoftware' beschreibt, dass der ein Schutz vor
Schadsoftware angewandt werden muss.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Basis"))
  exit(0);

title = "Schutz vor Schadsoftware";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Firewall state,
Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Inbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall with Advanced Security\Windows Firewall with Advanced Security\Windows Firewall Properties\Domain Profile\Outbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Domain Profile\SettingsCustomize\Display a notification,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Domain Profile\Logging Customize\Name,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Domain Profile\Logging Customize\Sizelimit (KB),
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Domain Profile\Logging Customize\Logdropped packets,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Domain Profile\Logging Customize\Logsuccessful connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Firewall state,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Inbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Outbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\SettingsCustomize\Display a notification,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Logging Customize\Name,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Logging Customize\Sizelimit (KB),
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Logging Customize\Logdropped packets,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Private Profile\Logging Customize\Logsuccessful connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Firewall state,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Inbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Outbound connections,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\SettingsCustomize\Display a notification,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Settings Customize\Applylocal firewall rules,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Settings Customize\Applylocal connection security rules,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Logging Customize\Name,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Logging Customize\Sizelimit (KB),
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Logging Customize\Logdropped packets,
Computer Configuration\Policies\Windows Settings\Security Settings\WindowsFirewall with Advanced Security\Windows Firewall with AdvancedSecurity\Windows Firewall Properties\Public Profile\Logging Customize\Logsuccessful connections,
Computer Configuration\Policies\Administrative Templates\MS Security Guide\Turn on Windows Defender protection against Potentially Unwanted Applications,
User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\Notify antivirus programs when opening attachments";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109552",
"1.3.6.1.4.1.25623.1.0.109553",
"1.3.6.1.4.1.25623.1.0.109554",
"1.3.6.1.4.1.25623.1.0.109555",
"1.3.6.1.4.1.25623.1.0.109556",
"1.3.6.1.4.1.25623.1.0.109557",
"1.3.6.1.4.1.25623.1.0.109558",
"1.3.6.1.4.1.25623.1.0.109559",
"1.3.6.1.4.1.25623.1.0.109560",
"1.3.6.1.4.1.25623.1.0.109561",
"1.3.6.1.4.1.25623.1.0.109562",
"1.3.6.1.4.1.25623.1.0.109563",
"1.3.6.1.4.1.25623.1.0.109564",
"1.3.6.1.4.1.25623.1.0.109565",
"1.3.6.1.4.1.25623.1.0.109566",
"1.3.6.1.4.1.25623.1.0.109567",
"1.3.6.1.4.1.25623.1.0.109568",
"1.3.6.1.4.1.25623.1.0.109569",
"1.3.6.1.4.1.25623.1.0.109570",
"1.3.6.1.4.1.25623.1.0.109571",
"1.3.6.1.4.1.25623.1.0.109193",
"1.3.6.1.4.1.25623.1.0.109194",
"1.3.6.1.4.1.25623.1.0.109572",
"1.3.6.1.4.1.25623.1.0.109573",
"1.3.6.1.4.1.25623.1.0.109574",
"1.3.6.1.4.1.25623.1.0.109575",
"1.3.6.1.4.1.25623.1.0.109315",
"1.3.6.1.4.1.25623.1.0.109519");

# Create and set kb entries for GSHB_Kompendium VT
if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
} else {
  results_list = itg_get_policy_control_result(oid_list:oid_list);
  result = itg_translate_result(compliant:results_list["compliant"]);
}
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A5");

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);
itg_report(report:report);

exit(0);