###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_aironet_cisco-sa-20171016-wpa.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Aironet Access Points Multiple WPA2 Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:cisco:wireless_lan_controller_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140433");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-17 09:54:27 +0700 (Tue, 17 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-13082");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Aironet Access Points Multiple WPA2 Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version", "cisco_wlc/model");

  script_tag(name:"summary", value:"Cisco Aironet Access Points are prone to key reinstallation attacks against
WPA protocol.");

  script_tag(name:"insight", value:"On October 16th, 2017, a research paper with the title of 'Key
Reinstallation Attacks: Forcing Nonce Reuse in WPA2' was made publicly available. This paper discusses seven
vulnerabilities affecting session key negotiation in both the Wi-Fi Protected Access (WPA) and the Wi-Fi Protected
Access II (WPA2) protocols. These vulnerabilities may allow the reinstallation of a pairwise transient key, a
group key, or an integrity key on either a wireless client or a wireless access point. Additional research also
led to the discovery of three additional vulnerabilities (not discussed in the original paper) affecting wireless
supplicant supporting either the 802.11z (Extensions to Direct-Link Setup) standard or the 802.11v (Wireless
Network Management) standard. The three additional vulnerabilities could also allow the reinstallation of a
pairwise key, group key, or integrity group key.");

  script_tag(name:"impact", value:"An attacker within the wireless communications range of an affected AP and
client may leverage packet decryption and injection, TCP connection hijacking, HTTP content injection, or the
replay of unicast, broadcast, and multicast frames.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("cisco_wlc/model");
if (!model || ((model !~ "^AIR-AP15(2|3|5|6|7)[0-9]") && (model !~ "^AIR-AP(7|16|17|26|35|36|37)[0-9]{2}") &&
               (model !~ "^AIR-AP(700|801|802|803)")))
  exit(0);

if (!version = get_app_version(cpe:CPE))
  exit(0);

if (version_is_less(version: version, test_version: "8.0.152.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.152.0");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^8\.2\.") {
  if (version_is_less(version: version, test_version: "8.2.164.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.2.164.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.3\.") {
  if (version_is_less(version: version, test_version: "8.3.130.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.3.130.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.5\.") {
  if (version_is_less(version: version, test_version: "8.5.105.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.105.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.6\.") {
  if (version_is_less(version: version, test_version: "8.6.100.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.6.100.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

