###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_spark_detect.nasl 12326 2018-11-13 05:25:34Z ckuersteiner $
#
# Apache Spark Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141675");
  script_version("$Revision: 12326 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 06:25:34 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-13 10:25:12 +0700 (Tue, 13 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Spark Detection");

  script_tag(name:"summary", value:"Detection of Apache Spark.

The script sends a connection request to the server and attempts to detect Apache Spark and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 6066, 7077);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://spark.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 7077);

res = http_get_cache(port: port, item: "/");

if ("serverSparkVersion" >< res && "Missing protocol version" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: '"serverSparkVersion" : "([0-9.]+)"', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "apache_spark/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:spark:");
  if (!cpe)
    cpe = 'cpe:/a:apache:spark';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache Spark", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
