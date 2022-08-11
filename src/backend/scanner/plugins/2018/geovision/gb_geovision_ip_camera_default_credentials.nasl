###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovision_ip_camera_default_credentials.nasl 11684 2018-09-28 13:01:56Z tpassfeld $
#
# GeoVision IP Camera Default Credentials
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114036");
  script_version("$Revision: 11684 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 15:01:56 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-28 11:55:31 +0200 (Fri, 28 Sep 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("GeoVision IP Camera Default Credentials");
  script_dependencies("gb_geovision_ip_camera_remote_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("geovision/ip_camera/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of GeoVision IP Camera is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of GeoVision IP Camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to GeoVision IP Camera is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:geovision:geovisionip_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

creds = make_array("admin", "admin");

url1 = "/ssi.cgi/Login.htm";
url2 = "/LoginPC.cgi";

foreach cred(keys(creds)) {

  req1 = http_get_req(port: port, url: url1, add_headers: make_array("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));

  res1 = http_keepalive_send_recv(port: port, data: req1);

  #var cc1="6D3D"; var cc2="C8C4";
  info = eregmatch(pattern: 'var cc1="([^"]+)"; var cc2="([^"]+)";', string: res1);
  if(isnull(info[1]) || isnull(info[2])) continue;
  cc1=info[1];
  cc2=info[2];

  #f.umd5.value=hex_md5(cc1+u.toLowerCase()+cc2);
  umd5 = toupper(hexstr(MD5(string(cc1, tolower(cred), cc2))));
  #f.pmd5.value=hex_md5(cc2+p.toLowerCase()+cc1);
  pmd5 = toupper(hexstr(MD5(string(cc2, tolower(creds[cred]), cc1))));

  #username=&password=&Apply=Apply&umd5=19F09FB3C8505A6E26858E0A3B565EE3&pmd5=8F1B57744E39DB5A9461791E45C11881&browser=1&is_check_OCX_OK=0
  data = "username=&password=&Apply=Apply&umd5=" + umd5 + "&pmd5=" + pmd5 + "&browser=1&is_check_OCX_OK=0";

  req2 = http_post_req(port: port, url: url2, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                  "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                                                                  "Accept-Language", "en-US,en;q=0.5",
                                                                                  "Content-Type", "application/x-www-form-urlencoded"));
  res2 = http_keepalive_send_recv(port: port, data: req2);

  if("IsAdmId() {return 1;}" >< res2) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';

    #Use the client ID in your following authenticated http-requests as a header. Example -> Cookie: CLIENT_ID=7714
    cid = eregmatch(pattern: 'CLIENT_ID=([0-9]+)', string: res2);
    if(isnull(cid[1])) set_kb_item(name: "geovision/ip_camera/client_id", value: cid[1]);
  }


}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
