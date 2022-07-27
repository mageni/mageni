###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webnms_file_upload_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# WebNMS 5.2 / 5.2 SP1 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:webnms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106242");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-13 17:11:16 +0700 (Tue, 13 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-6600", "CVE-2016-6601", "CVE-2016-6602", "CVE-2016-6603");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("WebNMS 5.2 / 5.2 SP1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_webnms_detect.nasl");
  script_require_ports("Services/www", 9090);
  script_mandatory_keys("webnms/installed");

  script_tag(name:"summary", value:"WebNMS Framework 5.2 / 5.2 SP1 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if FileUploadServlet is accessible.");

  script_tag(name:"insight", value:"WebNMS Framework allows unauthenticated remote attackers to:

  - upload a JSP file by using a directory traversal attack on the FileUploadServlet servlet and gain remote code execution
  under the user which the WebNMS server is running.

  - allows context-dependent attackers to obtain cleartext passwords by leveraging access to WEB-INF/conf/securitydbData.xml.

  - read arbitrary files via a .. (dot dot) in the fileName parameter to servlets/FetchFile.

  - bypass authentication and impersonate arbitrary users via the UserName HTTP header.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may execute arbitrary code under the
  user which the WebNMS server is running and to gain access to sensitive data on the host.");

  script_tag(name:"affected", value:"WebNMS Framework Server 5.2 and 5.2 SP1");

  script_tag(name:"solution", value:"See the referenced for a mitigation procedure.");

  script_xref(name:"URL", value:"https://forums.webnms.com/topic/recent-vulnerabilities-in-webnms-and-how-to-protect-the-server-against-them");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2712");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40229/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE)) exit(0);
if (!dir = get_app_location(cpe: CPE, port: port)) exit(0);

if (dir == "/") dir = "";
url = dir + "/servlets/FileUploadServlet";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

# The servlet seems to only allow PUT requests
if (res =~ "^HTTP/1\.[01] 405") {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
