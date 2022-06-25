###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hiddencobra_volgmer_trojan_detection.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# HIDDEN COBRA Trojan 'Volgmer' Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112144");
  script_version("$Revision: 12021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-29 16:06:33 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HIDDEN COBRA Trojan 'Volgmer' Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Malware");
  script_dependencies("smb_registry_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access");

  script_tag(name:"summary", value:"This script tries to detect indicators in the Windows registry for malicious tools used by North Korean APT group 'HIDDEN COBRA'.");
  script_tag(name:"vuldetect", value:"Checking for the existence of various registry keys that could be an indication of the trojan's presence.");
  script_tag(name:"insight", value:"As a backdoor Trojan, Volgmer has several capabilities including: gathering system information, updating service registry keys,
downloading and uploading files, executing commands, terminating processes, and listing directories.

It is suspected that spear phishing is the primary delivery mechanism for Volgmer infections. However, HIDDEN COBRA actors use a suite of custom tools,
some of which could also be used to initially compromise a system. Therefore, it is possible that additional HIDDEN COBRA malware may be present on network infrastructure compromised with Volgmer.

Volgmer payloads have been observed in 32-bit form as either executables or dynamic-link library (.dll) files.
The malware uses a custom binary protocol to beacon back to the command and control (C2) server, often via TCP port 8080 or 8088,
with some payloads implementing Secure Socket Layer (SSL) encryption to obfuscate communications.

Malicious actors commonly maintain persistence on a victim's system by installing the malware-as-a-service.
Volgmer queries the system and randomly selects a service in which to install a copy of itself. The malware then overwrites the ServiceDLL entry in the selected service's registry entry.
In some cases, HIDDEN COBRA actors give the created service a pseudo-random name that may be composed of various hardcoded words.");
  script_tag(name:"impact", value:"Successful exploitation will give an attacker the opportunity to steal your sensitive data and gain backdoor access to your system.");
  script_tag(name:"solution", value:"Check the reference and apply the 'Mitigation Recommendations' that are being explained at the bottom of the document.");

  script_xref(name:"URL", value:"https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-D_WHITE_S508C.PDF");

  exit(0);
}

include("smb_nt.inc");

subkey = "SYSTEM\CurrentControlSet\Control\WMI\Security";
malValues = make_list("f0012345-2a9c-bdf8-345d-345d67b542a1", "125463f3-2a9c-bdf0-d890-5a98b08d8898",
                      "2d54931A-47A9-b749-8e23-311921741dcd", "c72a93f5-47e6-4a2a-b13e-6AFE0479cb01");

report = 'The following suspicious values have been found inside the registry:\n\nRegistry Key:\n' + subkey + '\n\nBinary Values:';

foreach value(malValues) {
  bin = registry_get_binary(key:subkey, item:value);
  if (bin) {
    found = TRUE;
    report += '\n' + value;
  }
}

if (found) {
  security_message( port:0, data:report);
  exit(0);
}

exit(99);
