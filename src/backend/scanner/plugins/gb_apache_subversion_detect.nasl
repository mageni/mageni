# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804405");
  script_version("2022-06-03T07:48:46+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2014-04-03 15:54:53 +0530 (Thu, 03 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Subversion Detection");

  script_tag(name:"summary", value:"Detection of Apache Subversion.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/subversion", 3690);

  script_xref(name:"URL", value:"https://subversion.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 3690, proto: "subversion");

if (!soc = open_sock_tcp(port))
  exit(0);

res = recv(socket:soc, length:4096);

if (res =~ "^\( success \( [0-9] [0-9] \(.*\) \(.*") {
  version = "unknown";
  vt_strings = get_vt_strings();

  send(socket: soc, data:'( 2 ( edit-pipeline ) 24:svn://host/svn/' + vt_strings["default"] + '0x ) \r\n');
  res = recv(socket: soc, length: 4096);
  close(soc);

  vers = eregmatch(pattern: ".*subversion-([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "apache/subversion/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:subversion:");
  if (!cpe)
    cpe = "cpe:/a:apache:subversion";

  register_product(cpe: cpe, location: "/", port: port, service: "subversion");

  log_message(data: build_detection_report(app: "Subversion", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

close(soc);

exit(0);
