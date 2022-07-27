###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ziproxy_bof_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# Ziproxy PNG Image Processing Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901128");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_cve_id("CVE-2010-2350");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ziproxy PNG Image Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40156");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59510");
  script_xref(name:"URL", value:"http://ziproxy.cvs.sourceforge.net/viewvc/ziproxy/ziproxy-default/ChangeLog?revision=1.240&view=markup");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ziproxy_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Ziproxy/installed");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to execute arbitrary code
  on the system with elevated privileges or cause the application to crash.");
  script_tag(name:"affected", value:"Ziproxy version 3.1.0");
  script_tag(name:"insight", value:"The flaw is caused by a heap overflow error in the PNG decoder when processing
  malformed data, which could be exploited by attackers to crash an affected
  server or execute arbitrary code via a specially crafted PNG image.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest version of Ziproxy 3.1.1 or later.");
  script_tag(name:"summary", value:"The host is running Ziproxy server and is prone to buffer overflow
  vulnerability.");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/ziproxy/files/");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

zipPort = get_http_port( default:8080 );

ziproxyVer = get_kb_item("www/" + zipPort + "/Ziproxy");
if(!ziproxyVer){
  exit(0);
}

if(version_is_equal(version:ziproxyVer, test_version:"3.1.0")){
  security_message(zipPort);
}
