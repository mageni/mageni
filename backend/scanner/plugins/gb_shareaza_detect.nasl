###############################################################################
# OpenVAS Vulnerability Test
#
# Shareaza Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800603");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Shareaza Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Shareaza/banner");
  script_require_ports("Services/www", 6346);
  script_tag(name:"summary", value:"This script detects the installed version of Shareaza and
  sets the result in KB.");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Shareaza Version Detection";

shareazaPort = get_http_port(default:6346);
banner = get_http_banner(port:shareazaPort);

if("Shareaza" >< banner)
{
  shareazaVer = eregmatch(pattern:"Server: Shareaza ([0-9.]+)", string:banner);

  if(shareazaVer[1] != NULL)
  {
    set_kb_item(name:"shareaza/detected", value:TRUE);
    set_kb_item(name:"www/" + shareazaPort + "/Shareaza", value:shareazaVer[1]);
    log_message(data:"Shareaza version " + shareazaVer[1] + " was detected on the host");

    cpe = build_cpe(value:shareazaVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ryo-oh-ki:shareaza:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
