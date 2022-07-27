###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_haraka_detect.nasl 13461 2019-02-05 09:33:31Z cfischer $
#
# Haraka SMTP Server Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106546");
  script_version("$Revision: 13461 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:33:31 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-01-27 12:28:21 +0700 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Haraka SMTP Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"https://haraka.github.io/");

  script_tag(name:"summary", value:"Detection of Haraka SMTP Server

  The script sends a connection request to the server and attempts to detect Haraka SMTP server and its version
  number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");

port = get_smtp_port(default:25);

banner = get_smtp_banner(port: port);
quit = get_kb_item("smtp/fingerprints/" + port + "/quit_banner");
ehlo = get_kb_item("smtp/fingerprints/" + port + "/ehlo_banner");

if (("ESMTP Haraka" >< banner || "Haraka is at your service" >< ehlo) && "Have a jolly good day" >< quit) {

  install = port + "/tcp";
  version = "unknown";

  vers = eregmatch(pattern: "ESMTP Haraka ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "haraka/version", value: version);
  }

  set_kb_item(name: "haraka/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:haraka:haraka:");
  if (!cpe)
    cpe = "cpe:/a:haraka:haraka";

  register_product(cpe: cpe, location: install, port: port, service: "smtp");
  log_message(data: build_detection_report(app: "Haraka", version: version, install: install, cpe: cpe,
                                           concluded: vers[0]),
              port: port);
}

exit(0);