###############################################################################
# OpenVAS Vulnerability Test
# $Id: compliance_tests.nasl 11098 2018-08-23 14:32:47Z emoss $
#
# Compliance Tests
#
# Authors:
# Michael Wiegand <michael.wiegand@intevation.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.95888");
  script_version("$Revision: 11098 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-23 16:32:47 +0200 (Thu, 23 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compliance Tests");
  script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"general_note");
  script_copyright("Copyright (c) 2009-2015 Greenbone Networks GmbH");
  script_family("Compliance");

  script_add_preference(name:"Launch IT-Grundschutz (10. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (11. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (12. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (13. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch IT-Grundschutz (15. EL)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch latest IT-Grundschutz version", type:"checkbox", value:"no");
  script_add_preference(name:"Level of Security (IT-Grundschutz)", type:"radio", value:"Basis;Standard;Kern");
  script_add_preference(name:"Verbose IT-Grundschutz results", type:"checkbox", value:"no");
  script_add_preference(name:"Launch PCI-DSS (Version 2.0)", type:"checkbox", value:"no");
  script_add_preference(name:"Launch latest PCI-DSS version", type:"checkbox", value:"no");
  script_add_preference(name:"Verbose PCI-DSS results", type:"checkbox", value:"no");
  script_add_preference(name:"Launch Cyber Essentials", type:"checkbox", value:"no");
  script_add_preference(name:"Launch EU GDPR", type:"checkbox", value:"no");
  script_add_preference(name:"Verbose Policy Controls", type:"checkbox", value:"no");
  script_add_preference(name:"Launch Compliance Test", type:"checkbox", value:"no");
  script_add_preference(name:"PCI-DSS Berichtsprache/Report Language", type:"radio", value:"Deutsch;English");
  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN");
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU");
  script_add_preference(name:"Windows Domaenenfunktionsmodus", type:"radio", value:"Unbekannt;Windows 2000 gemischt und Windows 2000 pur;Windows Server 2003 Interim;Windows Server 2003;Windows Server 2008;Windows Server 2008 R2");

  script_tag(name:"summary", value:"This script controls various compliance tests like IT-Grundschutz.");
  exit(0);
}

launch_gshb_10 = script_get_preference("Launch IT-Grundschutz (10. EL)");
if (launch_gshb_10 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-10", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_11 = script_get_preference("Launch IT-Grundschutz (11. EL)");
if (launch_gshb_11 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-11", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_12 = script_get_preference("Launch IT-Grundschutz (12. EL)");
if (launch_gshb_12 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-12", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_13 = script_get_preference("Launch IT-Grundschutz (13. EL)");
if (launch_gshb_13 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-13", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb_15 = script_get_preference("Launch IT-Grundschutz (15. EL)");
if (launch_gshb_15 == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-15", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_gshb = script_get_preference("Launch latest IT-Grundschutz version");
if (launch_gshb == "yes") {
  set_kb_item(name: "Compliance/Launch/GSHB-ITG", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
  set_kb_item(name: "Compliance/Launch", value: TRUE);
}
verbose_gshb = script_get_preference("Verbose IT-Grundschutz results");
if (verbose_gshb == "no") {
  set_kb_item(name: "GSHB-10/silence", value: "Wahr");
  set_kb_item(name: "GSHB-11/silence", value: "Wahr");
  set_kb_item(name: "GSHB-12/silence", value: "Wahr");
  set_kb_item(name: "GSHB-13/silence", value: "Wahr");
  set_kb_item(name: "GSHB-15/silence", value: "Wahr");
  set_kb_item(name: "GSHB/silence", value: "Wahr");
}

security_level = script_get_preference("Level of Security (IT-Grundschutz)");
set_kb_item(name:"GSHB/level", value: security_level);

launch_pci_dss = script_get_preference("Launch PCI-DSS (Version 2.0)");
if (launch_pci_dss == "yes") {
  set_kb_item(name: "Compliance/Launch/PCI-DSS_2.0", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
launch_pci_dss = script_get_preference("Launch latest PCI-DSS version");
if (launch_pci_dss == "yes") {
  set_kb_item(name: "Compliance/Launch/PCI-DSS", value: TRUE);
  set_kb_item(name: "Compliance/Launch/GSHB", value: TRUE);
}
lang_pci_dss = script_get_preference("PCI-DSS Berichtsprache/Report Language");
if (lang_pci_dss == "Deutsch")  set_kb_item(name: "PCI-DSS/lang", value: "ger");
else if (lang_pci_dss == "English")  set_kb_item(name: "PCI-DSS/lang", value: "eng");
else set_kb_item(name: "PCI-DSS/lang", value: "eng");

verbose_pci_dss = script_get_preference("Verbose PCI-DSS results");
if (verbose_pci_dss == "no") {
  set_kb_item(name: "PCI-DSS/silence", value: "Wahr");
}

launch_ce = script_get_preference("Launch Cyber Essentials");
if(launch_ce == "yes"){
  set_kb_item(name: "Compliance/Launch/CE", value:TRUE);
  set_kb_item(name: "Compliance/Launch", value:TRUE);
}

launch_gdpr = script_get_preference("Launch EU GDPR");
if(launch_gdpr == "yes"){
  set_kb_item(name: "Compliance/Launch/GDPR", value:TRUE);
  set_kb_item(name: "Compliance/Launch", value:TRUE);
}

launch_compliance_result = script_get_preference("Launch Compliance Test");
if(launch_compliance_result == "yes"){
  set_kb_item(name: "Compliance/Launch/PolicyControlsSummary", value:TRUE);
  set_kb_item(name: "Compliance/Launch", value:TRUE);
}

verbose_policy_controls = script_get_preference("Verbose Policy Controls");
if (verbose_policy_controls == "yes"){
  set_kb_item(name: "Compliance/Launch", value: TRUE);
  set_kb_item(name: "Compliance/verbose", value: TRUE);
}

CN = script_get_preference("Testuser Common Name");
OU = script_get_preference("Testuser Organization Unit");
DomFunkMod = script_get_preference("Windows Domaenenfunktionsmodus");

if (DomFunkMod == "Unbekannt")DomFunk = "none";
else if (DomFunkMod == "Windows 2000 gemischt und Windows 2000 pur")DomFunk = "0";
else if (DomFunkMod == "Windows Server 2003 Interim")DomFunk = "1";
else if (DomFunkMod == "Windows Server 2003")DomFunk = "2";
else if (DomFunkMod == "Windows Server 2008")DomFunk = "3";
else if (DomFunkMod == "Windows Server 2008 R2")DomFunk = "4";
else if (!DomFunk)DomFunk = "none";

set_kb_item(name:"GSHB/CN", value:CN);
set_kb_item(name:"GSHB/OU", value:OU);
set_kb_item(name:"GSHB/DomFunkMod", value:DomFunk);

exit(0);


