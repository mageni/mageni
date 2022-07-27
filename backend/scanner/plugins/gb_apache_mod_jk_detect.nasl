##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_jk_detect.nasl 12927 2019-01-03 05:43:34Z ckuersteiner $
#
# Apache mod_jk Module Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800279");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12927 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 06:43:34 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Apache mod_jk Module Version Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mod_jk/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This script detects the installed version of Apache mod_jk Module
  and saves the result in KB.");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if ("mod_jk" >< banner) {
  vers = eregmatch(pattern:"mod_jk/([0-9.]+)", string:banner);
  if(!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "apache_modjk/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:mod_jk:");
  if (!cpe)
    cpe = 'cpe:/a:apache:mod_jk';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache mod_jk", version: version, install: "/", cpe: cpe,
                                           concluded: banner),
              port: port);
  exit(0);
}

exit(0);
