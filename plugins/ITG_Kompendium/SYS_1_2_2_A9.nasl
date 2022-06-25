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
  script_oid("1.3.6.1.4.1.25623.1.0.150017");
  script_version("2019-12-16T11:36:02+0000");
  script_tag(name:"last_modification", value:"2019-12-16 11:36:02 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-13 10:19:13 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.1.2.2.A9");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_1_2_2_Windows_Server_2012.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_inbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_outbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_publicfw_localconsecrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_publicfw_localfwrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_domainfw_localconsecrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_unicast_response.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_successful_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_notification.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_logging_size.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_inbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_successful_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_inbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_dropped_packets.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_domainfw_localfwrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_privatefw_localconsecrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_outbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_unicast_response.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_dropped_packets.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_logging_size.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_outbound_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_state.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_dropped_packets.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_notification.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_successful_connections.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_unicast_response.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_state.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_logging_name.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_logging_name.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_private_logging_size.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_advsec_privatefw_localfwrules.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_public_notification.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_state.nasl",
"Policy/WindowsGeneral/FirewallGPO/win_fw_domain_logging_name.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.1.2.2 ist die Absicherung von Microsoft
Windows Server 2012 und Microsoft Windows Server 2012 R2.

Die Standard-Anforderung 'A9: Lokale Kommunikationsfilterung' beschreibt, dass die
lokale Firewall moeglichst strikt eingestellt werden sollte.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");

if (!itg_start_requirement(level:"Standard"))
  exit(0);

title = "Lokale Kommunikationsfilterung";

desc = "Folgende Einstellungen werden getestet:
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Inbound connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Domain Profile: Outbound connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Settings: Apply local connection security rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Settings: Apply local firewall rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Domain Profile: Settings: Apply local connection security rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Allow unicast response,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Logging: Log successful connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Settings: Display a notification,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Logging: Size limit (KB),
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Inbound connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Logging: Log successful connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Domain Profile: Inbound connections,
Network/Network Connections/Windows Defender Firewall/Domain Profile/Windows Defender Firewall: Allow logging,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Domain Profile: Settings: Apply local firewall rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Settings: Apply local connection security rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Outbound connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Allow unicast response,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Logging: Log dropped packets,
Network/Network Connections/Windows Defender Firewall/Private Profile/Windows Defender Firewall: Allow logging,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Outbound connections,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Firewall state,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Logging: Log dropped packets,
Network/Network Connections/Windows Defender Firewall/Private Profile/Windows Defender Firewall: Prohibit notifications,
Network/Network Connections/Windows Defender Firewall/Private Profile/Windows Defender Firewall: Allow logging,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Domain Profile: Allow unicast response,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Firewall state,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Logging: Name,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Logging: Name,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Logging: Size limit (KB),
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Private Profile: Settings: Apply local firewall rules,
Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security/Windows Firewall Properties/Public Profile: Settings: Display a notification,
Network/Network Connections/Windows Defender Firewall/Public Profile/Windows Defender Firewall: Protect all network connections,
Network/Network Connections/Windows Defender Firewall/Public Profile/Windows Defender Firewall: Allow logging";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109561",
"1.3.6.1.4.1.25623.1.0.109554",
"1.3.6.1.4.1.25623.1.0.109194",
"1.3.6.1.4.1.25623.1.0.109193",
"1.3.6.1.4.1.25623.1.0.109933",
"1.3.6.1.4.1.25623.1.0.109936",
"1.3.6.1.4.1.25623.1.0.109575",
"1.3.6.1.4.1.25623.1.0.109563",
"1.3.6.1.4.1.25623.1.0.109573",
"1.3.6.1.4.1.25623.1.0.109569",
"1.3.6.1.4.1.25623.1.0.109567",
"1.3.6.1.4.1.25623.1.0.109553",
"1.3.6.1.4.1.25623.1.0.109558",
"1.3.6.1.4.1.25623.1.0.109937",
"1.3.6.1.4.1.25623.1.0.109932",
"1.3.6.1.4.1.25623.1.0.109562",
"1.3.6.1.4.1.25623.1.0.109935",
"1.3.6.1.4.1.25623.1.0.109566",
"1.3.6.1.4.1.25623.1.0.109557",
"1.3.6.1.4.1.25623.1.0.109570",
"1.3.6.1.4.1.25623.1.0.109568",
"1.3.6.1.4.1.25623.1.0.109574",
"1.3.6.1.4.1.25623.1.0.109555",
"1.3.6.1.4.1.25623.1.0.109559",
"1.3.6.1.4.1.25623.1.0.109934",
"1.3.6.1.4.1.25623.1.0.109560",
"1.3.6.1.4.1.25623.1.0.109564",
"1.3.6.1.4.1.25623.1.0.109572",
"1.3.6.1.4.1.25623.1.0.109565",
"1.3.6.1.4.1.25623.1.0.109931",
"1.3.6.1.4.1.25623.1.0.109571",
"1.3.6.1.4.1.25623.1.0.109552",
"1.3.6.1.4.1.25623.1.0.109556");

if (host_runs("windows_server_2012") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.2.2.A9");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);

# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.1.2.2.A9");
itg_report(report:report);

exit(0);