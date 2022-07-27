###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hikvision_ip_camera_default_credentials.nasl 12426 2018-11-19 17:35:36Z tpassfeld $
#
# Hikvision IP Camera Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.114041");
  script_version("$Revision: 12426 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 18:35:36 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 15:43:28 +0200 (Fri, 26 Oct 2018)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Hikvision IP Camera Default Credentials");
  script_dependencies("gb_hikvision_ip_camera_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("hikvision/ip_camera/detected");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of Hikvision IP camera is prone to
  a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Hikvision IP camera is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to Hikvision IP camera is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/a:hikvision:ip_camera";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

creds = make_array("admin", "12345");

url2 = "/ISAPI/Security/userCheck?timeStamp=" + unixtime();

foreach cred(keys(creds)) {

  #Url to check what authentication mechanism the host prefers to use
  url1 = "/ISAPI/Security/sessionLogin/capabilities?username=" + cred;

  req1 = http_get_req(port: port, url: url1);

  res1 = http_keepalive_send_recv(port: port, data: req1);
  if("<challenge>" >< res1 && "<iterations>" >< res1) {
    #<sessionID>14d870aca4245e903d48</sessionID>
    #<challenge>ac6195dfab4e56958527527b49cd29dc</challenge>
    #<iterations>100</iterations>
    info = eregmatch(pattern: "<sessionID>([0-9a-zA-Z]+)</sessionID>\s*\n?\s*<challenge>([0-9a-zA-Z]+)</challenge>\s*\n?\s*<iterations>([0-9]+)</iterations>", string: res1);

    #<isIrreversible>true</isIrreversible>
    #<salt>e5334873d18827f09f34c2c48f343b71ba3bd7006497d26929901f0b622725f5</salt>
    infoSalt = eregmatch(pattern: "<isIrreversible>([a-zA-Z]+)</isIrreversible>\s*\n?\s*<salt>([0-9a-zA-Z]+)</salt>", string: res1);
    if(isnull(info[1]) || isnull(info[2]) || isnull(info[3])) continue;
    sessionID = info[1];
    challenge = info[2];
    iterations = int(info[3]);

    #Salted challenge-response:
    if(!isnull(infoSalt[1]) && !isnull(infoSalt[2])) {
      if(infoSalt[1] =~ "(t|T)rue") isIrreversible = 1;
      else isIrreversible = 0;

      salt = infoSalt[2];

      if(isIrreversible) {
        pass = hexstr(SHA256(cred + salt + creds[cred]));
        pass = hexstr(SHA256(pass + challenge));
        for(a = 2; iterations > a; a++) pass = hexstr(SHA256(pass));
      }
      else {
        pass = hexstr(SHA256(creds[cred])) + challenge;
        for(a = 1; iterations > a; a++) pass = hexstr(SHA256(pass));
      }
    }
    #Unsalted challenge response:
    else {
      #Encrypt the password with itself "iterations"-times, after encrypting it for the first time and appending the challenge hash
      pass = hexstr(SHA256(creds[cred])) + challenge;
      for(m = 1; iterations > m; m++) pass = hexstr(SHA256(pass));
    }
    #<SessionLogin><userName>admin</userName><password>e4ac831aa0de166b2d7725611f1f0b4ae7a3207b9110410779a76e6354a59b14</password><sessionID>091322c23220371b3388</sessionID></SessionLogin>
    data = "<SessionLogin><userName>" + cred + "</userName><password>" + pass + "</password><sessionID>" + sessionID + "</sessionID></SessionLogin>";

    url3 = "/ISAPI/Security/sessionLogin?timeStamp=" + unixtime();

    req2 = http_post_req(port: port, url: url3, data: data, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                                    "If-Modified-Since", "0",
                                                                                    "X-Requested-With", "XMLHttpRequest",
                                                                                    "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"));
  }
  #Digest authentication:
  else if(("Digest qop=" >< res1 && "nonce=" >< res1) || ("Digest realm=" >< res1 && "nonce=" >< res1)) {
    #WWW-Authenticate: Digest realm="DVRNVRDVS", domain="::", qop="auth", nonce="16c2671a88d919b48d011bfe56765a0e:1540569274326", opaque="", algorithm="MD5", stale="FALSE"
    #WWW-Authenticate: Basic realm="DVRNVRDVS"
    info = eregmatch(pattern: 'WWW-Authenticate:\\s*Digest realm="([^"]+)",\\s*domain="[^"]+",\\s*qop="([^"]+)",\\s*nonce="([^"]+)",\\s*opaque="",\\s*algorithm="MD5"', string: res1);
    if(!isnull(info[1]) && !isnull(info[2]) && !isnull(info[3])) {
      realm = info[1];
      qop = info[2];
      nonce = info[3];
    }
    else {
      #WWW-Authenticate: Digest qop="auth", realm="I21AE", nonce="4e445244524446424d5463365a445930596a5978597a453d", stale="FALSE"
      #WWW-Authenticate: Basic realm="I21AE"
      info = eregmatch(pattern: 'WWW-Authenticate:\\s*Digest qop="([^"]+)",\\s*realm="([^"]+)",\\s*nonce="([^"]+)",', string: res1);
      if(isnull(info[1]) || isnull(info[2]) || isnull(info[3])) continue;
      qop = info[1];
      realm = info[2];
      nonce = info[3];
    }
    #Digest authentication according to the standard showcased here: https://code-maze.com/http-series-part-4/#digestauth
    cnonce = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789", length:16);
    nc = "00000001";

    ha1 = hexstr(MD5(string(cred, ":", realm, ":", creds[cred])));
    ha2 = hexstr(MD5(string("GET:", url2)));
    response = hexstr(MD5(string(ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2)));

    #Authorization: Digest username="admin", realm="DVRNVRDVS", nonce="fc5531416402b6104208866e5cd11b36:1540566204832", uri="/ISAPI/Security/userCheck?timeStamp=1540559005144",
    #algorithm=MD5, response="58056c87a21a751a7a674d0a6b2dd42e", qop=auth, nc=00000001, cnonce="5084c1c8e39746cb"
    auth = 'Digest username="' + cred + '", realm="' + realm + '", nonce="' + nonce + '", uri="' + url2 + '", algorithm=MD5, response="' + response + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '"';

    req2 = http_get_req(port: port, url: url2, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                       "If-Modified-Since", "0",
                                                                       "X-Requested-With", "XMLHttpRequest",
                                                                       "Authorization", auth));

  }
  else exit(99); #Not challenge-response or digest authentication(is usually never the case)

  res2 = http_keepalive_send_recv(port: port, data: req2);

  if("<statusValue>200</statusValue>" >< res2 && "<statusString>OK</statusString>" >< res2) {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }

}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
