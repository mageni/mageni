###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_replay_attack_vuln_lin.nasl 12636 2018-12-04 08:02:40Z cfischer $
#
# Tor Replay Attack Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900323");
  script_version("$Revision: 12636 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:02:40 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0654");
  script_name("Replay Attack Vulnerability in Tor (Linux)");
  script_xref(name:"URL", value:"http://blog.torproject.org/blog/one-cell-enough");
  script_xref(name:"URL", value:"http://www.blackhat.com/presentations/bh-dc-09/Fu/BlackHat-DC-09-Fu-Break-Tors-Anonymity.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.0.34 and prior on Linux.");

  script_tag(name:"insight", value:"Flaw is in the data flow at the end of the circuit which lets the attacker
  to modify the relayed data.");

  script_tag(name:"solution", value:"Upgrade to Tor version 0.2.1.25 or later.");

  script_tag(name:"summary", value:"This host is installed with Tor Anonymity Proxy and is prone
  to replay attack vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker cause replay attacks
  in the network and can compromise router functionalities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.torproject.org/download-unix.html.en");

  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(!torVer)
  exit(0);

if(version_is_less_equal(version:torVer, test_version:"0.2.0.34")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}