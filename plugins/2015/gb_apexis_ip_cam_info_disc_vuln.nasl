###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apexis_ip_cam_info_disc_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apexis IP CAM Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805070");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-17 11:22:32 +0530 (Wed, 17 Jun 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Apexis IP CAM Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host has Apexis IP Camera and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able read the sensitive information");

  script_tag(name:"insight", value:"The flaw is due to the camera is not
  restricting some files which are containing sensitive information.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Apexis IP CAM models,
  APM-H602-MPC
  APM-H803-MPC
  APM-H901-MPC
  APM-H501-MPC
  APM-H403-MPC
  APM-H804");

  script_tag(name:"solution", value:"As a workaround apply appropriate
  firewall rules.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37298");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132213");

  script_tag(name:"solution_type", value:"Workaround");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.apexis.com.cn");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

apexCamPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/cgi-bin", cgi_dirs(port:apexCamPort)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir,"/get_status.cgi"), port:apexCamPort);
  rcvRes = http_keepalive_send_recv(port:apexCamPort, data:sndReq);

  if("ret_prot_mode='APM-H" >< rcvRes)
  {
    url = dir + "/get_tutk_account.cgi";
    if(http_vuln_check(port:apexCamPort, url:url, check_header:TRUE,
     pattern:"ret_tutk_user=", extra_check:"ret_tutk_pwd="))
    {
      security_message(port:apexCamPort);
      exit(0);
    }
  }
}

exit(99);
