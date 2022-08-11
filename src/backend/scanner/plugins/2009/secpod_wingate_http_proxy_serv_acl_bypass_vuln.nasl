###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wingate_http_proxy_serv_acl_bypass_vuln.nasl 12676 2018-12-05 15:27:20Z cfischer $
#
# Qbik WinGate HTTP Proxy Server Access Controls Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900325");
  script_version("$Revision: 12676 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:27:20 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0802");
  script_bugtraq_id(33858);
  script_name("Qbik WinGate HTTP Proxy Server Access Controls Bypass Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34020");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/435052");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wingate_detect.nasl");
  script_mandatory_keys("WinGate/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker obtain sensitive information
  i.e. Intranet webpage details.");

  script_tag(name:"affected", value:"WinGate version 6.0 to 6.5.2 Build 1217.");

  script_tag(name:"insight", value:"This issue occurs when the proxy makes a forwarding decision based on the
  'Host' HTTP header instead of the destination IP address while the proxy
  server works in transparent interception mode.");

  script_tag(name:"solution", value:"Upgrade to latest version.");

  script_tag(name:"summary", value:"This host is running WinGate HTTP Proxy Server and is prone to
  access controls bypass vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");

winGateVer = get_kb_item("WinGate/Ver");
if(!winGateVer) exit(0);

if(version_in_range(version:winGateVer, test_version:"6.0", test_version2:"6.5.2.1217")){
  security_message(port:0);
}

exit(0);