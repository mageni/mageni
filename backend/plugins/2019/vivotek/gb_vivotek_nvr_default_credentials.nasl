# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114061");
  script_version("2019-05-07T10:20:37+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-07 10:20:37 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-03 13:36:20 +0200 (Fri, 03 May 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Vivotek NVR Default Credentials");
  script_dependencies("gb_vivotek_nvr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vivotek/nvr/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/research/blog/default-passwords-for-most-ip-network-camera-brands/");
  script_xref(name:"URL", value:"https://www.use-ip.co.uk/forum/threads/vivotek-default-login-username-and-password.384/");

  script_tag(name:"summary", value:"The remote installation of Vivotek NVR is using known
  and deffault credentials for its web interface.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Vivotek NVR is lacking a proper
  password configuration, which makes critical information and actions accessible to anyone.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the IP camera management software is possible.");

  script_tag(name:"solution", value:"Change the default credentials.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("dump.inc");

CPE = "cpe:/a:vivotek:nvr";

if(!port = get_app_port(cpe: CPE, service: "www")) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT in the GSA

creds = make_array("admin", "admin");

url1 = "/fcgi-bin/system.key";
url2 = "/fcgi-bin/system.login";

foreach cred(keys(creds)) {

  username = creds[cred];
  password = cred;

  #Acquire modulus and exponent
  cookie = "_SID_=; username=" + username + "; nvr_user=; mode=liveview";

  req = http_get_req(port: port, url: url1, add_headers: make_array("Cookie", cookie));

  res = http_send_recv(port: port, data: req);

  #{"e": "10001", "n": "AA0AC324669F458AA38F45D6DC5E4859DCF6062F3F8F0596DD6D3CEB8F3AE8C4C5F9198711B348A0F66FD919FAB87E46EAA62B68ED68F0530828EF62B3FCCA27"}
  expMod = eregmatch(pattern: '\\{"e":\\s*"([01]+)",\\s*"n":\\s*"([0-9a-fA-F]+)"\\}', string: res);
  if(!isnull(expMod[1]) && !isnull(expMod[2])) {
    modLength = strlen(expMod[2]);
    #This is due to hex2raw somehow stripping the first character from uneven strings
    #We need to make the string of even length.
    if(strlen(expMod[1]) % 2) {
      expMod[1] = '0' + expMod[1];
    }
    if(strlen(expMod[2]) % 2) {
      expMod[2] = '0' + expMod[2];
    }
    rsa_exponent = hex2raw(s: expMod[1]);
    rsa_modulus = hex2raw(s: expMod[2]);
  } else exit(99);

  pad = rand_str(charset:"abcdef0123456789", length: 8);

  text = ":" + username + ":" + password;

  #Replication of the source code to handle moduli of different length differently as well.
  #This directly affects the hash that is being calculated based on substrings of the padding.
  if(modLength == 256) {
    seg_l = 117;
    encode_l = 234;
  } else {
    seg_l = 53;
    encode_l = 159;
  }

  pad_l = encode_l - strlen(text);

  for(i = strlen(pad); i < pad_l; i += i) {
    pad += pad;
  }

  text = substr(pad, 0, pad_l-1) + text;

  for(l = 0; l < encode_l; l += seg_l) {
    #Note: Change 'pad: "TRUE"' to 'pad: TRUE' once GVM 9 is retired!
    resultHash += hexstr(rsa_public_encrypt(data: substr(text, l, l + seg_l), e: rsa_exponent, n: rsa_modulus, pad: "TRUE"));
  }

  auth = "Basic " + resultHash;

  data = "encode=" + resultHash  + "&mode=liveview";

  req = http_post_req(port: port, url: url2, data: data, add_headers: make_array("Authorization", auth));
  res = http_send_recv(port: port, data: req);

  if('{"username":' >< res && '"encoder":' >< res) {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
