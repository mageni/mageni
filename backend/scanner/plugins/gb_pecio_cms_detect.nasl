###############################################################################
# OpenVAS Vulnerability Test
#
# Pecio CMS Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801443");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pecio CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Pecio CMS and
  sets the result in KB.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

cmsPort = get_http_port(default:80);
if (!can_host_php(port:cmsPort)) exit(0);

foreach dir (make_list_unique("/pecio", "/pecio_cms", cgi_dirs(port:cmsPort))) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:cmsPort);

  if('content="pecio cms'>< rcvRes)
  {
    cmsVer = eregmatch(pattern:"pecio cms ([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      tmp_version = cmsVer[1] + " under " + install;
      set_kb_item(name:"www/" + cmsPort + "/Pecio_CMS", value:tmp_version);
      set_kb_item(name:"pecio_cms/detected", value:TRUE);

      log_message(data:"Pecio CMS version " + cmsVer[1] +
       " running at location " + install + " was detected on the host");

      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:pecio-cms:pecio_cms:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe);
    }
  }
}
