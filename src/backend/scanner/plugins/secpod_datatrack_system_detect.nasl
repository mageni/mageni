###############################################################################
# OpenVAS Vulnerability Test
#
# DataTrack System Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902061");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DataTrack System Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_require_ports("Services/www", 81);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed DataTrack System version and saves
  the result in KB.");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "DataTrack System Version Detection";

dtsPort = get_http_port(default:81);
banner = get_http_banner(port:dtsPort);

if("Server: MagnoWare" >< banner || ">DataTrack Web Client<" >< banner)
{
  dtsVer = eregmatch(pattern:"MagnoWare/([0-9.]+)", string:banner);
  if(dtsVer[1] != NULL)
  {
    set_kb_item(name:"www/" + dtsPort + "/DataTrack_System", value:dtsVer[1]);
    set_kb_item(name:"datatrack_system/detected", value:TRUE);

    log_message(data:"DataTrack System version " + dtsVer[1] + " was detected on the host");

    cpe = build_cpe(value:dtsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:magnoware:datatrack_system:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
