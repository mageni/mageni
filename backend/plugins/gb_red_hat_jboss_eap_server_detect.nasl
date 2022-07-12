###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_red_hat_jboss_eap_server_detect.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# Red Hat JBoss EAP Server Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810306");
  script_version("$Revision: 10905 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-12-09 12:11:43 +0530 (Fri, 09 Dec 2016)");
  script_name("Red Hat JBoss EAP Server Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Red Hat JBoss EAP Server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("JBoss-EAP/banner");
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


jbossport = get_http_port(default:443);

banner = get_http_banner(port: jbossport);
if("JBoss-EAP" >!< banner) {
  exit(0);
}

install = "/";

jbossver = eregmatch(pattern:"Server: JBoss-EAP/([0-9.]+)", string:banner);
if(jbossver[1]){
  jbossver = jbossver[1];
}
else{
  jbossver ="Unknown";
}

set_kb_item(name:"www/" + jbossport + "/", value:jbossver);
set_kb_item(name:"Redhat/JBoss/EAP/Installed", value:TRUE);

cpe = build_cpe(value:jbossver, exp:"^([0-9.]+)", base:"cpe:/a:redhat:jboss_enterprise_application_platform:");
if(!cpe)
  cpe= "cpe:/a:redhat:jboss_enterprise_application_platform";

register_product(cpe:cpe, location:install, port:jbossport);

log_message(data: build_detection_report(app: "Red Hat JBoss EAP",
                                         version: jbossver,
                                         install: install,
                                         cpe: cpe,
                                         concluded: jbossver),
                                         port: jbossport);
exit(0);
