###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fuzzylime_cms_local_file_inc_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# fuzzylime cms code/track.php Local File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800314");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5291");
  script_bugtraq_id(32475);
  script_name("fuzzylime cms code/track.php Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32865");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7231");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will cause inclusion and execution of arbitrary
  files from local resources via directory traversal attacks.");
  script_tag(name:"affected", value:"fuzzylime cms version 3.03 and prior.");
  script_tag(name:"insight", value:"The flaw is caused due improper handling of input passed to p parameter
  in code/track.php file when the url, title and excerpt form parameters
  are set to non-null values.");
  script_tag(name:"solution", value:"Update to fuzzylime cms version 3.03a or later.");
  script_tag(name:"summary", value:"The host is running fuzzylime CMS and is prone to Local File
  Inclusion vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach path (make_list_unique("/fuzzylime/_cms303", cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/docs/readme.txt", port:port);
  if(!rcvRes)
    continue;

  if("fuzzylime (cms)" >< rcvRes)
  {
    cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      if(version_is_less_equal(version:cmsVer[1], test_version:"3.03")){
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);