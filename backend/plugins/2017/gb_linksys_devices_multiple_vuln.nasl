###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_devices_multiple_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Linksys Devices Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:linksys:devices";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812040");
  script_version("$Revision: 11977 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-19 11:57:11 +0530 (Thu, 19 Oct 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Linksys Devices Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running linksys device and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and confirm
  the vulnerability from the response.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A crafted GET request can reboot the whole device or freeze the web interface
    and the DHCP service. This action does not require authentication.

  - An error in the web service, so a header injection can be triggered without
    authentication.

  - The session ID for administrative users can be fetched from the device from
    LAN without credentials because of insecure session handling.

  - An attacker can change any configuration of the device by luring a user to
    click on a malicious link or surf to a malicious web-site.

  - Insufficient validation of user input in Admin Interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service, HTTP header injection, open redirect,
  information disclosure, CSRF and XSS attacks on the affected device.");

  script_tag(name:"affected", value:"Linksys E2500 firmware version 3.0.02 (build 2)

  Linksys E900 firmware version 1.0.06

  Linksys E1200 firmware version 2.0.07 (build 5)

  Linksys E8400 AC2400 Dual-Band Wi-Fi Router

  Linksys E900-ME firmware version: 1.0.06

  Linksys E1500 firmware version: 1.0.06 (build 1)

  Linksys E3200 firmware version: 1.0.05 (build 2)

  Linksys E4200 firmware version: 1.0.06 (build 3)

  Linksys WRT54G2 firmware version: 1.5.02 (build 5)

  This list may not be accurate and/or complete!");

  script_tag(name:"solution", value:"Update to the latest available firmware.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43013");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/541369/30/0/threaded");
  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/multiple-vulnerabilities-in-linksys-e-series-products/index.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("gb_linksys_devices_detect.nasl");
  script_mandatory_keys("Linksys/detected");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!netPort = get_app_port(cpe:CPE)){
  exit(0);
}

postData = "submit_type=&submit_button=UnsecuredEnable&gui_action=Apply" +
           "&wait_time=19&next_url=www.example.com&change_action=";

##Request and Response
url = '/UnsecuredEnable.cgi';
req = http_post_req( port: netPort, url: url, data: postData);
res = http_keepalive_send_recv( port:netPort , data: req );

if(res && res =~ "HTTP/1.. 302" && res =~ "Location.*http://www.example.com")
{
  report = report_vuln_url(port:netPort, url:url);
  security_message( port:netPort, data:report);
  exit(0);
}
exit(0);
