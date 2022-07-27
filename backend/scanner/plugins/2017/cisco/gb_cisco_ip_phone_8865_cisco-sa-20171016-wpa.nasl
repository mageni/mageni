###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ip_phone_8865_cisco-sa-20171016-wpa.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IP Phone 8865 Multiple WPA2 Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140452");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 10:19:05 +0700 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081",
                "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco IP Phone 8865 Multiple WPA2 Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_ip_phone_detect.nasl");
  script_mandatory_keys("cisco/ip_phone/model");

  script_tag(name:"summary", value:"Cisco IP Phone 8865 is prone to key reinstallation attacks against
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

  script_tag(name:"solution", value:"Update to version 12.0.1SR1 or later.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171016-wpa");

  exit(0);
}

include("version_func.inc");

if (!model = get_kb_item("cisco/ip_phone/model"))
  exit(0);

if (model =~ "^CP-8865") {
  if (!version = get_kb_item("cisco/ip_phone/version"))
    exit(0);

  version = eregmatch(pattern: "sip8845_65\.([0-9SR-]+)", string: version);

  if (!isnull(version[1])) {
    version = ereg_replace(string: version[1], pattern: "-", replace: ".");
    if (version_is_less(version: version, test_version: "12.0.1SR1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "12.0.1SR1");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
