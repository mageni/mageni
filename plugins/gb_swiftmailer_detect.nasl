###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swiftmailer_detect.nasl 11894 2018-10-13 07:46:55Z cfischer $
#
# SwiftMailer Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809772");
  script_version("$Revision: 11894 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-13 09:46:55 +0200 (Sat, 13 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-29 17:59:59 +0530 (Thu, 29 Dec 2016)");
  script_name("SwiftMailer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of SwiftMailer Library.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

phpPort = get_http_port(default:80);
if(!can_host_php(port:phpPort)) exit(0);

foreach dir(make_list_unique("/", "/swiftmailer", "/SwiftMailer", cgi_dirs(port:phpPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  foreach path (make_list("", "/lib"))
  {
    foreach file (make_list("/composer.json", "/README", "/CHANGES", "/"))
    {
      res = http_get_cache(item: dir + path + file, port:phpPort);

      if((res =~ "^HTTP/1\.[01] 200") &&
         ('swiftmailer"' >< res && '"MIT"' >< res && 'swiftmailer.org"' >< res) ||
         ("Swift Mailer, by Chris Corbyn" >< res && "swiftmailer.org" >< res)||
         ("Swift_Mailer::batchSend" >< res && "Swiftmailer" >< res))
      {
        foreach verfile (make_list("/VERSION", "/version"))
        {
          res1 = http_get_cache(item: dir + path + verfile, port:phpPort);

          if(res1 =~ "^HTTP/1\.[01] 200")
          {
            version = eregmatch(pattern:'Swift-([0-9.]+)([A-Za-z0-9]-)?', string: res1);
            if(version[1])
            {
              version = version[1];
              version = ereg_replace(pattern:"-", string:version, replace:".");

              set_kb_item(name:"www/" + phpPort + "/swiftmailer", value:version);
              set_kb_item(name:"swiftmailer/Installed", value:TRUE);

              # CPE not registered yet
              cpe = build_cpe( value:version, exp:"([0-9A-Za-z.]+)", base:"cpe:/a:swiftmailer:swiftmailer:");
              if( isnull(cpe ))
                cpe = 'cpe:/a:swiftmailer:swiftmailer';

              register_product(cpe:cpe, location:install, port:phpPort);

              log_message(data:build_detection_report(app:"SwiftMailer",
                                                      version:version,
                                                      install:install,
                                                      cpe:cpe,
                                                      concluded:version),
                                                      port:phpPort);
              exit(0);
            }
          }
        }
      }
    }
  }
}
exit(0);
