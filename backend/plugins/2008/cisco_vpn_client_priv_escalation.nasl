# OpenVAS Vulnerability Test
# $Id: cisco_vpn_client_priv_escalation.nasl 11555 2018-09-22 15:24:22Z cfischer $
# Description: Cisco VPN Client Privilege Escalation Vulnerability
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.25550");
  script_version("$Revision: 11555 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:24:22 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2006-2679");
  script_bugtraq_id(18094);
  script_name("Cisco VPN Client Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Windows");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_mandatory_keys("SMB/CiscoVPNClient/Version");
  script_tag(name:"solution", value:"Upgrade to version 4.8.01.0300 or a later.");
  script_tag(name:"summary", value:"The remote windows host contains an application that is affected by a
privilege escalation vulnerability.

Description :

The installed Cisco VPN Client version is prone to a privilege
escalation attack.  By using the 'Start before logon' feature in the
VPN client dialer, a local attacker may gain privileges and execute
arbitrary commands with SYSTEM privileges.");
  script_xref(name:"URL", value:"http://www.cisco.com/warp/public/707/cisco-sa-20060524-vpnclient.shtml");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

version = get_kb_item("SMB/CiscoVPNClient/Version");
if (version) {
	# These versions are reported vulnerable:
	# - 2.x, 3.x, 4.0.x, 4.6.x, 4.7.x, 4.8.00.x
	# Not vulnerable:
	# - 4.7.00.0533
 	if ("4.7.00.0533" >< version) exit(0);
	if (egrep(pattern:"^([23]\.|4\.([067]\.|8\.00)).+", string:version)) {
		security_message(port:get_kb_item("SMB/transport"));
	}
}
