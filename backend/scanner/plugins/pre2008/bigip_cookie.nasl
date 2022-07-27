# OpenVAS Vulnerability Test
# Description: F5 BIG-IP Cookie Persistence
#
# Authors:
# Jon Passki - Shavlik Technologies, LLC <jon.passki@shavlik.com>
#
# Copyright:
# Copyright (C) 2005 Shavlik Technologies, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20089");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("F5 BIG-IP Cookie Persistence");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Shavlik Technologies, LLC");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20051214144937/asia.f5.com/solutions/archives/techbriefs/cookie.html");

  script_tag(name:"solution", value:"Change the Cookie mode. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote load balancer suffers from an information disclosure
  vulnerability.");

  script_tag(name:"insight", value:"The remote host appears to be a F5 BigIP load balancer which encodes
  within a cookie the IP address of the actual web server it is acting on behalf of. Additionally, information
  after 'BIGipServer' is configured by the user and may be the logical name of the device. These values may
  disclose sensitive information, such as internal IP addresses and names.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);

# Number of HTTP connections.
# - gets reset if a new cookie is found.
retries = 5;
# - max number of retries (does not get reset).
max_retries = 10;
flag = 0;

while(retries-- && max_retries--) {
  soc = http_open_socket(port);
  if ( ! soc && flag == 0 )
    exit(0);
  else if( ! soc )  {
    report_error = 1;
    break;
  }
  flag++;

  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  http_headers = http_recv_headers2(socket:soc);
  http_close_socket(soc);

  # If this cookie is replayed in subsequent requests,
  # the load balancer will have an affinity with the back end.
  # This might be a good knowledge base entry.
  enc_ip = enc_port = NULL;
  pat = "^Set-Cookie:.*(BIGipServer([^=]+)=([0-9]+)\.([0-9]+)\.[0-9]+)";
  matches = egrep(pattern:pat, string:http_headers);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      cookie = eregmatch(pattern:pat, string:match);
      if (!isnull(cookie)) {
        this_cookie = cookie[1];
        cookie_jar[this_cookie]++;
        debug_print("cookie: ", this_cookie, ".");
        enc_ip = cookie[3];
        enc_port = cookie[4];
        break;
      }
    }
  }
  if (isnull(enc_ip) || isnull(enc_port)) {
    report_error = 2;
    break;
  }

  # If the cookie is new....
  if (isnull(ips[this_cookie]) || isnull(ips[this_cookie])) {
    # Decode the cookie.
    #
    # nb: IP "a.b.c.d" is encoded as "d*256^3 + c*256^2 + b*256 + a".
    dec_ip = string(
      ( enc_ip & 0x000000ff)      , ".",
      ((enc_ip & 0x0000ffff) >> 8), ".",
      ((enc_ip & 0x00ffffff) >> 16), ".",
      (enc_ip >> 24)
    );
    debug_print("ip: ", enc_ip, " -> ", dec_ip, ".");

    # nb: port is merely byte-swapped.
    dec_port = (enc_port & 0x00ff) * 256 + (enc_port >> 8);
    debug_print("port: ", enc_port, " -> ", dec_port, ".");

    # Stash them for later.
    ips[this_cookie] = dec_ip;
    ports[this_cookie] = dec_port;

    # Keep trying to enumerate backend hosts.
    retries = 3;
  }
}


# Generate a report if we got at least one cookie.
if (this_cookie) {
  if(report_error == 1)
    report = " The script failed in making a socket connection to the target system after a previous connection worked. This may affect the completeness of the report and you might wish to rerun this test again on the targeted system.";
  else if(report_error == 2)
    report = "The script failed in finding a BIG-IP cookie on the target system after a previous cookie was found.  This may affect the completeness of the report and you might wish to rerun this test again on the targeted system.";

  report += "The first column is the original cookie, the second the IP address and the third the TCP port:";
  foreach cookie (keys(cookie_jar)) {
    report = string(report, "\n", "  ", cookie, "\t", ips[cookie], "\t", ports[cookie]);
  }
  security_message(port:port, data:report);
  exit(0);
}

exit(99);