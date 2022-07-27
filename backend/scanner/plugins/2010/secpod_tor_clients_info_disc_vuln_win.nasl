###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_clients_info_disc_vuln_win.nasl 12635 2018-12-04 08:00:20Z cfischer $
#
# Tor Clients Information Disclosure Vulnerability (win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902102");
  script_version("$Revision: 12635 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 09:00:20 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0384");
  script_name("Tor Clients Information Disclosure Vulnerability (win)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38198");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jan-2010/msg00000.html");
  script_xref(name:"URL", value:"http://www.torproject.org/download.html.en");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.2.x before 0.2.2.7-alpha on Windows.");

  script_tag(name:"insight", value:"This issue is due to directory mirror which does not prevent logging of the
  client IP address upon detection of erroneous client behavior, which might make
  it easier for local users to discover the identities of clients by reading log files.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.2.7-alpha");

  script_tag(name:"summary", value:"This host is installed with Tor and is prone to Information Disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain client IP information
  that can help them launch further attacks.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
if(torVer =~ "^0\.2\.2\."){
  if(version_is_less(version:torVer, test_version:"0.2.2.7.alpha")){
    security_message(port:0);
    exit(0);
  }
}