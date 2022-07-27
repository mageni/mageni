##############################################################################
# OpenVAS Vulnerability Test
#
# Brekeke PBX Cross-Site Request Forgery Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902066");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2114");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Brekeke PBX Cross-Site Request Forgery Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39952");
  script_xref(name:"URL", value:"http://cross-site-scripting.blogspot.com/2010/05/brekeke-pbx-2448-cross-site-request.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 28080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists in the application which fails to perform
  validity checks on certain 'HTTP reqests', which allows an attacker to hijack
  the authentication of users for requests that change passwords via the
  pbxadmin.web.PbxUserEdit bean.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Brekeke PBX version 2.4.6.7 or later.");

  script_tag(name:"summary", value:"This host is running Brekeke PBX and is prone to Cross-Site
  Request Forgery Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to change the
  administrator's password by tricking a logged in administrator into visiting a
  malicious web site.");

  script_tag(name:"affected", value:"Brekeke PBX version 2.4.4.8");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

pbxPort = get_http_port(default:28080);

sndReq = http_get(item:string("/pbx/gate?bean=pbxadmin.web.PbxLogin"), port:pbxPort);
rcvRes = http_send_recv(port:pbxPort, data:sndReq);

if(">Brekeke PBX<" >< rcvRes)
{
  pbxVer = eregmatch(pattern:"Version ([0-9.]+)" , string:rcvRes);
  if(pbxVer[1] != NULL)
  {
    if(version_is_equal(version:pbxVer[1], test_version:"2.4.4.8")){
      security_message(pbxPort);
    }
  }
}
