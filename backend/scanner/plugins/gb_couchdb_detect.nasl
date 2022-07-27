###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_couchdb_detect.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# CouchDB Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100571");
  script_version("$Revision: 13650 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 07:48:40 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CouchDB Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("CouchDB/banner");
  script_require_ports("Services/www", 5984);

  script_tag(name:"summary", value:"This host is running CouchDB. Apache CouchDB is a document-oriented
  database that can be queried and indexed in a MapReduce fashion using
  JavaScript. CouchDB also offers incremental replication with
  bi-directional conflict detection and resolution.");

  script_xref(name:"URL", value:"http://couchdb.apache.org/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");

port = get_http_port(default:5984);
banner = get_http_banner(port: port);
if(!banner || "Server: CouchDB/" >!< banner)
  exit(0);

set_kb_item(name: "couchdb/installed", value:TRUE);

vers = "unknown";

version = eregmatch(pattern:"Server: CouchDB/([^ ]+)", string: banner);

if(!isnull(version[1])) {

  vers = version[1];
  set_kb_item(name: "couchdb/version", value: vers);
  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:apache:couchdb:");

  if (!cpe)
    cpe = "cpe:/a:apache:couchdb";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache CouchDB",
                                           version: vers,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: version[0]),
                                           port: port);
}

exit(0);