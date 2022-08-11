###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cmailserver_detect.nasl 13397 2019-02-01 08:06:48Z cfischer $
#
# CMailServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900917");
  script_version("$Revision: 13397 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 09:06:48 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CMailServer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"The script detects the installed version of a CMailServer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("cpe.inc");
include("host_details.inc");

smtpPorts = smtp_get_ports();
foreach port(smtpPorts){

  banner = get_smtp_banner(port: port);
  if(banner && "CMailServer" >< banner){

    set_kb_item(name: "CMailServer/Installed", value: TRUE);
    ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
    version = "unknown";

    if(ver[1]){
      version = ver[1];
      set_kb_item(name: "CMailServer/Ver", value: version);
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
    if (!cpe)
      cpe = "cpe:/a:youngzsoft:cmailserver";

    register_product(cpe: cpe, location: "/", port: port, service: "smtp");

    log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                             version: version,
                                             install: "/",
                                             cpe: cpe,
                                             concluded: ver[0]),
                                             port: port);
  }
}

imapPorts = imap_get_ports();
foreach port(imapPorts){

  banner = get_imap_banner(port: port);
  if(banner && "CMailServer" >< banner){

    set_kb_item(name: "CMailServer/Installed", value: TRUE);
    ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
    version = "unknown";

    if(ver[1]){
      version = ver[1];
      set_kb_item(name: "CMailServer/Ver", value: version);
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
    if (!cpe)
      cpe = "cpe:/a:youngzsoft:cmailserver";

    register_product(cpe: cpe, location: "/", port: port, service: "imap");

    log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                             version: version,
                                             install: "/",
                                             cpe: cpe,
                                             concluded: ver[0]),
                                             port: port);
  }
}

popPorts = pop3_get_ports();
foreach port(popPorts){

  banner = get_pop3_banner(port: port);

  if(banner && "CMailServer" >< banner){

    set_kb_item(name: "CMailServer/Installed", value: TRUE);
    ver = eregmatch(pattern: "CMailServer ([0-9.]+)", string: banner);
    version = "unknown";

    if(ver[1]){
      version = ver[1];
      set_kb_item(name: "CMailServer/Ver", value: version);
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:youngzsoft:cmailserver:");
    if (!cpe)
      cpe = "cpe:/a:youngzsoft:cmailserver";

    register_product(cpe: cpe, location: "/", port: port, service: "pop3");

    log_message(data: build_detection_report(app: "Youngzsoft CMailServer",
                                             version: version,
                                             install: "/",
                                             cpe: cpe,
                                             concluded: ver[0]),
                                             port: port);
  }
}

exit(0);