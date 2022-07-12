###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_dns_spoofing_vuln_jul09_win.nasl 12635 2018-12-04 08:00:20Z cfischer $
#
# Tor 'relay.c' DNS Spoofing Vulnerability - July09 (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800838");
  script_version("$Revision: 12635 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:00:20 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2426");
  script_bugtraq_id(35505);
  script_name("Tor 'relay.c' DNS Spoofing Vulnerability - July09 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35546");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51377");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jun-2009/msg00000.html");
  script_xref(name:"URL", value:"http://www.torproject.org/download.html.en");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.x before 0.2.0.35 and 0.1.x before 0.1.2.8-beta on Windows.");

  script_tag(name:"insight", value:"Error in 'connection_edge_process_relay_cell_not_open' function in 'relay.c'
  in src/or/ allows exit relays to have an unspecified impact by causing
  controllers to accept DNS responses that redirect to an internal IP address via unknown vectors.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.0.35 or 0.1.2.8-beta or later.");

  script_tag(name:"summary", value:"This host is installed with Tor and is prone to DNS Spoofing vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct DNS spoofing attacks.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);

if(version_in_range(version:torVer, test_version:"0.1", test_version2:"0.1.2.8.alpha")||
   version_in_range(version:torVer, test_version:"0.2", test_version2:"0.2.0.34.alpha")) {
  security_message(port:0);
  exit(0);
}
