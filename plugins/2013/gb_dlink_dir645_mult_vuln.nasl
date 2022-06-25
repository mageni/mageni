###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir645_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# D-Link DIR-645 Router Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803730");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-7389");
  script_bugtraq_id(61579);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-05 15:17:38 +0530 (Mon, 05 Aug 2013)");
  script_name("D-Link DIR-645 Router Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running D-Link DIR-645 Router and is prone to multiple
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP request and check whether it is able to read
  the cookie or not.");
  script_tag(name:"solution", value:"Upgrade to version 1.04B11, or higher.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Buffer overflow in post_login.xml, hedwig.cgi and authentication.cgi
   When handling specially crafted requests.

  - Input passed to the 'deviceid' parameter in bind.php, 'RESULT' parameter
   in info.php and 'receiver' parameter in bsc_sms_send.php is not properly
   sanitised before being returned to the user.");
  script_tag(name:"affected", value:"D-Link DIR-645 firmware version 1.04 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause denial of service or
  execute arbitrary HTML and script code in a user's browser session in context of an affected website.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27283");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/17");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/527705");
  script_xref(name:"URL", value:"http://roberto.greyhats.it/advisories/20130801-dlink-dir645.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/hardware/d-link-dir-645-103b08-multiple-vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("DIR-645/banner");

  script_xref(name:"URL", value:"http://www.dlink.com/ca/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port: port);
if(banner && "DIR-645" >!< banner){
  exit(0);
}

req = http_get(item: "/", port:port);
res = http_send_recv(port:port,data:req);

if(">D-LINK SYSTEMS" >< res && ">DIR-645<" >< res)
{
  url = '/parentalcontrols/bind.php?deviceid="><script>alert' +
        '(document.cookie)</script><';

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:"><script>alert\(document.cookie\)</script><",
                     extra_check:make_list("OpenDNS", "overriteDeviceID")))
  {
    report = report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
