###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rabbitmq_amqp_detect.nasl 14045 2019-03-08 07:18:46Z cfischer $
#
# RabbitMQ Detection (AMPQ)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106498");
  script_version("$Revision: 14045 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 08:18:46 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-06 16:52:19 +0700 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RabbitMQ Detection (AMPQ)");

  script_tag(name:"summary", value:"This script performs AMQP based detection of RabbitMQ.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_amqp_detect.nasl");
  script_require_ports("Services/amqp", 5672);
  script_mandatory_keys("amqp/installed");

  exit(0);
}

include("cpe.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_port_for_service(default: 5672, proto: "amqp");

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

version_raw = get_kb_item("amqp/" + port + "/version/raw");
if (!version_raw)
  exit(0);

req = raw_string('AMQP', 0, version_raw);
send( socket:soc, data:req );
res = recv( socket:soc, min:8, length:1024 );

res = bin2string(ddata: res, noprint_replacement: ' ');

if (ereg(pattern: "productSRabbitMQ.", string: res)) {
  version = "unknown";

  vers = eregmatch(pattern: "versionS([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "rabbitmq/version", value: version);
  }

  set_kb_item(name: "rabbitmq/installed", value: TRUE);
  set_kb_item(name: "rabbitmq/amqp/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:pivotal_software:rabbitmq:");
  if (!cpe)
    cpe = 'cpe:/a:pivotal_software:rabbitmq';

  register_product(cpe: cpe, port: port, service: "amqp");

  log_message(data: build_detection_report(app: "RabbitMQ", version: version, install: port + "/amqp", cpe: cpe,
                                           concluded: res),
              port: port);
}

exit(0);