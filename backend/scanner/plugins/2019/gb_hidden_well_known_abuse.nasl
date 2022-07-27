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
  script_oid("1.3.6.1.4.1.25623.1.0.108564");
  script_version("2019-04-05T11:40:39+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-05 11:40:39 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-05 09:31:46 +0000 (Fri, 05 Apr 2019)");
  script_name("Shade/Troldesh Ransomware Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Malware");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host seems to be hosting files within hidden directories
  used to spread the Shade/Troldesh ransomware.");

  script_tag(name:"vuldetect", value:"Sends HTTP GET requests to various known Indicator of Compromise (IOC) files within the
  /.well-known/acme-challenge/ and /.well-known/pki-validation/ folders and checks the response.");

  script_tag(name:"insight", value:"In 2019 it was found that unknown threat actors are known to target WordPress and Jommla
  installation via known vulnerabilities with the goal to misuse the target system to host files of the Shade/Troldesh ransomware
  for various hacking and phishing campaings.");

  script_tag(name:"solution", value:"A whole cleanup of the infected system is recommended.");

  script_xref(name:"URL", value:"https://www.zscaler.de/blogs/research/abuse-hidden-well-known-directory-https-sites");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("dump.inc");
include("misc_func.inc");

# nb: See https://www.zscaler.de/blogs/research/abuse-hidden-well-known-directory-https-sites for a list of IoCs
iocs = make_array(
  "error_log", "^\[[0-9 -:a-zA-Z]+\] ", # Contains e.g. something like [12-Mar-2019 22:58:44 UTC] PHP Deprecated:  preg_replace(): The /e modifier is deprecated, use preg_replace_callback instead
  # nb: The .jpg and .pdf files are the Ransomware / .exe files
  "msg.jpg", "This program cannot be run in DOS mode",
  "msges.jpg", "This program cannot be run in DOS mode",
  "ssj.jpg", "This program cannot be run in DOS mode",
  "messg.jpg", "This program cannot be run in DOS mode",
  "sserv.jpg", "This program cannot be run in DOS mode",
  "ssj.jpg", "This program cannot be run in DOS mode",
  "nba1.jpg", "This program cannot be run in DOS mode",
  "mxr.pdf", "This program cannot be run in DOS mode",
  # nb: The .htm contains the download link / iframe to .zip files
  "inst.htm", '^<html>.+<iframe src="["^]+\\.zip"',
  "thn.htm", '^<html>.+<iframe src="["^]+\\.zip"',
  # nb: And finllay the .zip are just zip archives...
  # the zip file will be checked via a raw string below...
  "pik.zip", "",
  "reso.zip", "",
  "tehnikol.zip", "",
  "stroi-industr.zip", "",
  "gkpik.zip", "",
  "major.zip", "",
  "rolf.zip", "",
  "pic.zip", "",
  "kia.zip", "",
  "stroi-invest.zip", ""
);

report = ""; # nb: To make openvas-nasl-lint happy...

port = get_http_port( default:80 );

foreach dir( make_list( "/.well-known/acme-challenge/", "/.well-known/pki-validation/" ) ) {

  # nb: Basic false positive check for servers responding with a 200 to invalid requests.
  req = http_get( port:port, item:dir + rand() );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]{3}" || res =~ "^HTTP/1\.[01] (200|5[0-9]{2})" )
    continue;

  foreach ioc( keys( iocs ) ) {

    pattern = iocs[ioc];

    url = dir + ioc;
    req = http_get( port:port, item:url );

    if( ".zip" >< ioc ) {
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      if( ! res || strlen( res ) < 4 )
        continue;

      # See e.g. https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
      if( substr( res, 0, 3 ) == raw_string( 0x50, 0x4B, 0x03, 0x04 ) ) {
        report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
        VULN = TRUE;
      }
    } else {
      res = http_keepalive_send_recv( port:port, data:req );
      if( ! res || res !~ "^HTTP/1\.[01] 200" )
        continue;

      # nb: eregmatch below can handle binary data so we need to use this first.
      res = bin2string( ddata:res );

      if( eregmatch( string:res, pattern:pattern, icase:FALSE ) ) {
        report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
        VULN = TRUE;
      }
    }
  }
}

if( VULN ) {
  report = 'The following IOCs where identified. NOTE: Please take care when opening the files as these might contain malicious code:\n' + report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
