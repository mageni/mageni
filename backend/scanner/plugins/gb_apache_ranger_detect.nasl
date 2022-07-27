###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ranger_detect.nasl 60298 2016-11-29 19:00:32 Nov$
#
# Apache Ranger Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809483");
  script_version("$Revision: 11020 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:35:00 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-02 19:00:32 +0530 (Fri, 02 Dec 2016)");
  script_name("Apache Ranger Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Apache Ranger.

  This script sends HTTP GET request and try to get the version of
  Apache Ranger from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 6080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

rangerport = get_http_port( default:6080);

rcvRes = http_get_cache( item:"/login.jsp" , port:rangerport );

if(rcvRes =~ "HTTP/1.. 200" && '<title> Ranger - Sign In</title>' >< rcvRes &&
   '> Username:<' >< rcvRes  && '> Password:<' >< rcvRes)
{
  version = "unknown";
  install = "/";

  set_kb_item(name:"Apache/Ranger/Installed", value:TRUE);

  cpe = "cpe:/a:apache:ranger";

  register_product(cpe:cpe, location:install, port:rangerport);

  log_message( data:build_detection_report( app:"Apache Ranger",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version ),
                                            port:rangerport );
}
exit(0);
