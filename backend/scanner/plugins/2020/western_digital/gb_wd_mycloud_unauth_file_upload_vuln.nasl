# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108955");
  script_version("2020-10-21T10:59:59+0000");
  script_tag(name:"last_modification", value:"2020-10-22 10:10:52 +0000 (Thu, 22 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 10:09:10 +0000 (Wed, 21 Oct 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2019-9951");
  script_name("Western Digital My Cloud Unauthenticated File Upload Vulnerability (Active Check)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");

  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-firmware-versions-2-31-174-3-26-19/235932");
  script_xref(name:"URL", value:"https://github.com/bnbdr/wd-rce/");
  script_xref(name:"URL", value:"https://bnbdr.github.io/posts/wd/");

  script_tag(name:"summary", value:"Western Digital My Cloud is prone to an unauthenticatedfile upload vulnerability.");

  script_tag(name:"insight", value:"The page web/jquery/uploader/uploadify.php can be accesses without any credentials
  and allows uploading arbitrary files to any location on the attached storage under either:

  - /mnt/HD

  - /mnt/USB

  - /mnt/isoMount");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the reference for
  more details and downloads.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || "my_cloud" >!< CPE )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/web/jquery/uploader/uploadify.php";

# nb: If the target is accessed via a DNS name it might respond with something like:
# <b>Warning</b>:  gethostbyaddr(): Address is not a valid IPv4 or IPv6 address
# and a 200 status code instead of the expected response below so we're always
# using the IP address in the host header.
req = http_get_req( port:port, url:url, host_header_use_ip:TRUE );
res = http_keepalive_send_recv( port:port, data:req );

# nb: Different devices seems to answer differently (but always with a 200 status code):
#
# MyCloud Mirror with firmware version 2.11.178
#
# <b>Warning</b>:  session_start(): Cannot send session cache limiter - headers already sent (output started at /usr/local/modules/web/pages/jquery/uploader/uploadify.php:3) in <b>/usr/local/modules/web/pages/jquery/uploader/uploadify.php</b> on line <b>3</b><br />
# {"success":false}
#
# MyCloud EX2 Ultra with firmware version 2.31.149
#
# {"success":false}
#
# A fixed system always answers with a "Forbidden" 403 status code.
if( res =~ "^HTTP/1\.[01] 200" && res =~ '\\{"success":false\\}$' ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
