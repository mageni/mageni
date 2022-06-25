###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adh_webserver_ip_cameras_mult_vuln.nasl 11423 2018-09-17 07:35:16Z cfischer $
#
# ADH-Web Server IP-Cameras Multiple Improper Access Restrictions Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806058");
  script_version("$Revision: 11423 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 09:35:16 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-22 15:57:38 +0530 (Tue, 22 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ADH-Web Server IP-Cameras Multiple Improper Access Restrictions Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ADH-Web Server
  IP-Camera and is prone to multiple access restrictions vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain valuable information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Insufficient validation of user supplied input via 'variable' in
    variable.cgi script.

  - Unauthenticated access of all files on the cameras.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain access to valuable information such as access credentials,
  Network configuration and other sensitive information in plain text.");

  script_tag(name:"affected", value:"ADH-Web Server IP-Cameras,

  SD Advanced Closed IPTV,

  SD Advanced,

  EcoSense,

  Digital Sprite 2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38245");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133634");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

ipCamPort = get_http_port(default:80);

sndReq = http_get(item:"/gui/gui_outer_frame.shtml", port:ipCamPort);
rcvRes = http_send_recv(port:ipCamPort, data:sndReq);

if("ipCamera" >< rcvRes && "Server: ADH-Web" >< rcvRes)
{
  url = "/variable.cgi?variable=camconfig[0]&slaveip=127.0.0.1";

  if(http_vuln_check(port:ipCamPort, url:url, check_header:TRUE,
     pattern:"telm_cam_protocol=",
     extra_check:make_list("supported_streams=", "aspect_ratio=", "lens_type=")))
  {
    report = report_vuln_url( port:ipCamPort, url:url );
    security_message(port:ipCamPort, data:report);
    exit(0);
  }
}
