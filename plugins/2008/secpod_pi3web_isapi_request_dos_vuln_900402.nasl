##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pi3web_isapi_request_dos_vuln_900402.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: Pi3Web ISAPI Requests Handling DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900402");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6938");
  script_bugtraq_id(32287);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_name("Pi3Web ISAPI Requests Handling DoS Vulnerability");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Pi3Web/banner");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7109/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32696/");
  script_xref(name:"URL", value:"http://pi3web.sourceforge.net/pi3web/files/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32287/info/");

  script_tag(name:"impact", value:"Successful exploitation will crash Pi3Web Server.");

  script_tag(name:"insight", value:"This vulnerability is due to insufficient checks on incoming HTTP
  requests in the 'ISAPI' directory. This can be exploited via 'install.daf',
  'readme.daf', or 'users.txt' files in the affected directory.");

  script_tag(name:"summary", value:"Pi3Web is prone to ISAPI Requests Handling DoS vulnerability.");

  script_tag(name:"affected", value:"Pi3Wed.org Pi3Web version 2.0.13 and prior on all running platforms.");

  script_tag(name:"solution", value:"- Disable ISAPI mapping in server configuration in Server Admin-> Mapping Tab.

  - Delete the users.txt, install.daf and readme.daf in ISAPI folder.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Pi3Web" >!< banner)
  exit(0);

if(safe_checks()) {
  if(egrep(pattern:"Pi3Web/(^[01](\..*)|2\.0(\.[0-3])?)", string:banner)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

req = http_get(item:"/isapi/users.txt", port:port);
res = http_send_recv(port:port, data:req);
if("500 Internal Error" >< res){
  security_message(port:port);
}

exit(99);