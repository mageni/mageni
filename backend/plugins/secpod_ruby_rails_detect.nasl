###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# Ruby on Rails Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 2011-07-05
#    -Modified the regex for detecting beta versions.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902089");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_name("Ruby on Rails Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running Ruby on Rails version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

rorPort = get_http_port( default:3000 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", cgi_dirs( port:rorPort ) ) ) {

  if(rootInstalled) break;

  install = dir;
  if(dir == "/") dir = "";

  sndReq = http_get(item:dir + "/rails/info/properties/", port:rorPort);
  rcvRes = http_keepalive_send_recv(port:rorPort, data:sndReq);
  sndReq2 = http_get(item:dir + "/doesnt_exist/", port:rorPort);
  rcvRes2 = http_keepalive_send_recv(port:rorPort, data:sndReq2);
  sndReq3 = http_get(item:dir + "/rails/info/routes/", port:rorPort);
  rcvRes3 = http_keepalive_send_recv(port:rorPort, data:sndReq3);

  if(">Ruby version<" >< rcvRes || ">Rails version<" >< rcvRes || "<title>Routes</title>" >< rcvRes ||
     "<title>Action Controller: Exception caught</title>" >< rcvRes2 || "<title>Routes</title>" >< rcvRes3) {

    rorVersion = "unknown";
    railsVersion = "unknown";
    if(dir == "") rootInstalled = 1;

    rorVer = eregmatch(pattern:">Rails version.*([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rcvRes);
    if(rorVer[0] != NULL) {
      extra = "Version information available at /rails/info/properties/";
      rorVer = eregmatch(pattern:">([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rorVer[0]);

      if(rorVer[1] != NULL) {
        if(rorVer[3] != NULL) {
          rorVersion = rorVer[1] + rorVer[2];
        } else {
          rorVersion = rorVer[1];
        }
      }
    }

    if(rorVersion != "unknown")
      set_kb_item(name:"www/" + rorPort + "/Ruby/Rails/Ver", value:rorVersion);

    set_kb_item(name:"RubyOnRails/installed", value:TRUE);

    cpe = build_cpe(value:rorVersion, exp:"^([0-9.]+)", base:"cpe:/a:rubyonrails:ruby_on_rails:");
    if(isnull(cpe))
       cpe = 'cpe:/a:rubyonrails:ruby_on_rails';
    register_product(cpe:cpe, location: install, port: rorPort);

    log_message(data: build_detection_report(app:"Ruby on Rails",
                                             version:rorVersion,
                                             install:install,
                                             cpe:cpe,
                                             concluded:rorVer[0],
                                             extra:extra),
                                             port:rorPort);

    rubyVer = eregmatch(pattern:">Ruby version.*([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rcvRes);
    if(rubyVer[0] != NULL) {
       extra = "Version information available at /rails/info/properties/";
       rubyVer = eregmatch(pattern:">([0-9.]+)(.?([a-zA-Z0-9]+))?", string:rubyVer[0]);

      if(rubyVer[1] != NULL) {
        if(rubyVer[3] != NULL) {
          rubyVersion = rubyVer[1] + rubyVer[2];
        } else {
          rubyVersion = rubyVer[1];
        }
      }
    }

    cpe = build_cpe(value:rubyVersion, exp:"^([0-9.]+)", base:"cpe:/a:ruby-lang:ruby:");
    if(isnull(cpe))
       cpe = 'cpe:/a:ruby-lang:ruby';
    register_product(cpe:cpe, location: install, port: rorPort);

    log_message(data: build_detection_report(app:"Ruby",
                                             version:rubyVersion,
                                             install:install,
                                             cpe:cpe,
                                             concluded:rubyVer[0],
                                             extra:extra),
                                             port:rorPort);
  }
}

exit(0);