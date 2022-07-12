###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_b2evolution_detect.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# b2evolution Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900712");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("b2evolution Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed b2evolution script and saves the
  version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

b2Port = get_http_port(default:80);
if(!can_host_php(port:b2Port)){
  exit(0);
}

foreach path (make_list_unique("/blogs/htsrv", "/b2evolution/blogs/htsrv", cgi_dirs(port:b2Port)))
{

  install = path;
  if(path == "/") path = "";

  response = http_get_cache(item: path + "/login.php", port:b2Port);

  if("b2evolution" >< response)
  {
    b2Ver = eregmatch(pattern:"b2evolution ([0-9.]+)", string:response);
    if(b2Ver[1] != NULL)
    {
      tmp_version = b2Ver[1] + " under " + install;
      set_kb_item(name:"www/" + b2Port + "/b2evolution",
                  value:tmp_version);
      log_message(data:"b2evolution Version " + b2Ver[1] +
                " running at location " + install +  " was detected on the host");

      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:b2evolution:b2evolution:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe);

    }
  }
}
