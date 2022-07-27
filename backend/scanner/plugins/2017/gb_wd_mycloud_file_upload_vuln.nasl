###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_file_upload_vuln.nasl 12561 2018-11-28 13:48:33Z cfischer $
#
# WD MyCloud File Upload Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140610");
  script_version("$Revision: 12561 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 14:48:33 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-19 09:48:55 +0700 (Tue, 19 Dec 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-17560");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WD MyCloud File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");

  script_tag(name:"summary", value:"Western Digital MyCloud is prone to a file upload vulnerability.");

  script_tag(name:"insight", value:"The /web/jquery/uploader/multi_uploadify.php PHP script provides multipart
  upload functionality that is accessible without authentication and can be used to place a file anywhere on the
  device's file system. This allows an attacker the ability to upload a PHP shell onto the device and obtain
  arbitrary code execution as root.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the reference for
  more details and downloads.");

  script_xref(name:"URL", value:"http://gulftech.org/advisories/WDMyCloud%20Multiple%20Vulnerabilities/125");
  script_xref(name:"URL", value:"https://www.exploitee.rs/index.php/Western_Digital_MyCloud");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43356/");
  script_xref(name:"URL", value:"http://support.wdc.com/downloads.aspx?lang=en#firmware");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || "my_cloud" >!< CPE )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + '/web/jquery/uploader/multi_uploadify.php';

# nb: If the target is accessed via a DNS name it might respond with something like:
# <b>Warning</b>:  gethostbyaddr(): Address is not a valid IPv4 or IPv6 address
# and a 200 status code instead of the expected response below
req = http_get_req(port: port, url: url, host_header_use_ip: TRUE);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "HTTP/1\.[01] 302" && "Location: ?status=1" >< res) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);