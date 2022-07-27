###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ioserver_mult_dir_trav_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# IOServer Trailing Backslash Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802445");
  script_version("$Revision: 13543 $");
  script_cve_id("CVE-2012-4680");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-08-20 16:21:46 +0530 (Mon, 20 Aug 2012)");
  script_name("IOServer Trailing Backslash Multiple Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://www.foofus.net/?page_id=616");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Aug/223");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("IOServer/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"IOServer version 1.0.18.0 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper validation of URI containing
  ../ (dot dot) sequences, which allows attackers to read arbitrary files
   via directory traversal attacks.");
  script_tag(name:"solution", value:"Upgrade to IOServer version 1.0.19.0 or later.");
  script_tag(name:"summary", value:"This host is running IOServer and is prone to multiple directory
  traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.ioserver.com/");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:81);

banner = get_http_banner(port: port);
if("Server: IOServer" >!< banner) {
  exit(0);
}

files = traversal_files("windows");

foreach file ( keys( files ) ) {

  url = "/.../.../.../.../" + files[file];
  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url( port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);