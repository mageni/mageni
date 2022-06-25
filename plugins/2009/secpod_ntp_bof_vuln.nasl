###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900623");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0159");
  script_bugtraq_id(34481);
  script_name("NTP Stack Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34608");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49838");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0999");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("NTP/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code or to cause the application to crash.");
  script_tag(name:"affected", value:"NTP versions prior to 4.2.4p7-RC2 on Linux.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error within the cookedprint()
  function in ntpq/ntpq.c while processing malicious response from
  a specially crafted remote time server.");
  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.4p7-RC2.");
  script_tag(name:"summary", value:"This host has NTP installed and is prone to stack buffer overflow
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");

ntpPort = 123;
if(!get_udp_port_state(ntpPort)){
  exit(0);
}

fullVer = get_kb_item("NTP/Linux/FullVer");
if(fullVer && fullVer == "ntpd 4.2.4p4@1.1520-o Sun Nov 22 17:34:54 UTC 2009 (1)") {
  exit(0); # debian backport
}

ntpVer = get_kb_item("NTP/Linux/Ver");
if(!ntpVer){
  exit(0);
}

if (revcomp(a: ntpVer, b: "4.2.4p7.RC2") < 0) {
  security_message(port:ntpPort, proto:"udp");
}
