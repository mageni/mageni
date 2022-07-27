###############################################################################
# OpenVAS Vulnerability Test
#
# NaviCOPA Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801100");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NaviCOPA Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("NaviCOPA/banner");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"This script detects the version of installed NaviCOPA Server
  and saves the result in KB.");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "NaviCOPA Server Version Detection";

httpPort = get_http_port( default:80 );

banner = get_http_banner(port:httpPort);
if("NaviCOPA" >< banner)
{
  ncpaVer = eregmatch(pattern:"Version ([0-9.]+)", string:banner);
  if(!isnull(ncpaVer[1]))
  {
    set_kb_item(name:"NaviCOPA/" + httpPort + "/Ver", value:ncpaVer[1]);
    set_kb_item(name:"navicopa/detected", value:TRUE);
    log_message(data:"NaviCOPA Server version " + ncpaVer[1] +
                     " was detected on the host");

    cpe = build_cpe(value:ncpaVer[1], exp:"^([0-9.]+)", base:"cpe:/a:intervations:navicopa_web_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
