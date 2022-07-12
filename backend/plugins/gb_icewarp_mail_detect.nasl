###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_mail_detect.nasl 13397 2019-02-01 08:06:48Z cfischer $
#
# IceWarp Mail Server Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140330");
  script_version("$Revision: 13397 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 09:06:48 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-28 15:51:57 +0700 (Mon, 28 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IceWarp Mail Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_xref(name:"URL", value:"http://www.icewarp.com/");

  script_tag(name:"summary", value:"Detection of IceWarp Mail Server.

  The script sends a connection request to the server and attempts to detect IceWarp Mail Server and to
  extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

function _report(port, version, concluded, service)
{
  if (!version || version == '')
    return;

  set_kb_item(name: "icewarp/installed", value: TRUE);
  set_kb_item(name: "icewarp/mail/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:icewarp:mail_server:");
  if (!cpe)
    cpe = 'cpe:/a:icewarp:mail_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: service);

  log_message(data: build_detection_report(app: "IceWarp", version: version, install: port + '/tcp', cpe: cpe,
                                           concluded: concluded),
              port: port);
  return;
}

ports = smtp_get_ports();
foreach port (ports) {

  banner = get_smtp_banner(port: port);

  if ("ESMTP IceWarp" >< banner) {
    if (vers = eregmatch(pattern: "ESMTP IceWarp ([0-9.]+)", string: banner)) {
      _report(port: port, version: vers[1], concluded: banner, service: "smtp");
    }
  }
}

ports = imap_get_ports();
foreach port (ports) {

  banner = get_imap_banner(port: port);
  if ("IceWarp" >< banner) {
    if (vers = eregmatch(pattern: "IceWarp ([0-9.]+)", string: banner)) {
      _report(port: port, version: vers[1], concluded: banner, service: "imap");
    }
  }
}

ports = pop3_get_ports();
foreach port (ports) {

  banner = get_pop3_banner(port: port);
  if ("IceWarp" >< banner) {
    if (vers = eregmatch(pattern: "IceWarp ([0-9.]+)", string: banner)) {
      _report(port: port, version: vers[1], concluded: banner, service: "pop3");
    }
  }
}

exit(0);