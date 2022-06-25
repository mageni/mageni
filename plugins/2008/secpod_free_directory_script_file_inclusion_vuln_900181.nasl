##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_free_directory_script_file_inclusion_vuln_900181.nasl 14245 2019-03-18 06:33:51Z cfischer $
# Description: Free Directory Script 'API_HOME_DIR' File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900181");
  script_version("$Revision: 14245 $");
  script_cve_id("CVE-2008-6305");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 07:33:51 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_name("Free Directory Script 'API_HOME_DIR' File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7155");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32745");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker add, modify or delete files
  from the server and can let the attacker install trojans or backdoors.");
  script_tag(name:"insight", value:"The Error occurs when passing an input parameter into the 'API_HOME_DIR' in
  'init.php' file which is not properly verified before being used to include
  files. This can be exploited to include arbitrary files from local or external resources.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Free Directory Script and is prone to
  File Inclusion Vulnerability.");
  script_tag(name:"affected", value:"Free Directory Script version 1.1.1 and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach path (make_list_unique("/FreeDirectory", cgi_dirs(port:port)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item:path + "/index.php", port:port);
  if(!rcvRes)
    continue;

  if(egrep(pattern:"Free Directory Script", string:rcvRes) && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes)) {
    pattern = "FDS Version (0(\..*)|1\.(0(\..*)?|1(\.[01])?))($|[^.0-9])";
    if(egrep(pattern:pattern, string:rcvRes)){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);