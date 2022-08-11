###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_avc787_dvr_default_cred_vuln.nasl 12928 2019-01-03 08:54:17Z ckuersteiner $
#
# AVTech AVC 787 DVR Web Interface Default Credentials Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813818");
  script_version("2019-03-27T10:56:08+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-27 10:56:08 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("AVTech AVC 787 DVR Web Interface Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running an AVTech AVC 787 DVR
  device and is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends crafted data via an HTTP POST request
  and checks whether it is possible to login or not.");

  script_tag(name:"insight", value:"The installation of Amcrest's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker
  to bypass authentication and launch further attacks.");

  script_tag(name:"affected", value:"All AVTech AVC 787 DVR devices.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_xref(name:"URL", value:"http://www.avtech.hk/english/products5_1_787.htm");
  script_xref(name:"URL", value:"http://www.praetorianprefect.com/2009/12/shodan-cracking-ip-surveillance-dvr");
  script_xref(name:"URL", value:"http://www.smartvisiondirect.com/doc/avtech_avc_series_security_dvr_networking_howto_guide.pdf");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_dependencies("gb_avtech_avc7xx_dvr_device_detect.nasl");
  script_mandatory_keys("avtech/avc7xx/dvr/detected");
  exit(0);
}

include("url_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/o:avtech:avc7xx_dvr";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

creds = make_array("admin", "admin");

url = "/home.cgi";

hostType = get_kb_item("avtech/avc7xx/dvr/host_type");

foreach cred(keys(creds)) {

  if(hostType == "SQ_Webcam") {
    url = "/home.htm";
    #username=admin&password=admin&Submit=Submit
    data = "username=" + cred + "&password=" + creds[cred] + "&Submit=Submit";
  } else if(hostType == "Video_Web_Server") {
    baseURL = report_vuln_url(port: port, url: "/", url_only: TRUE);

    #username=admin&password=abc&url=http%3A%2F%2F69.159.77.249%2F&Submit=Submit
    data = "username=" + cred + "&password=" + creds[cred] + "&url=" + urlencode(str: baseURL, uppercase: TRUE) + "&Submit=Submit";
  } else exit(0);

  req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

  res = http_keepalive_send_recv(port: port, data: req);

  if(res =~ "---\s*Video Web Server\s*---") {
    VULN = TRUE;
    if(!password)
      password = "<no/empty password>";
    report += '\n' + cred + ':' + creds[cred];
  }

}

if(VULN) {
  report = 'It was possible to login with the following default credentials (username:password):\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
