###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_isilon_onefs_ftp_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# EMC Isilon OneFS Devices Detection (FTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106553");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-01-30 15:26:27 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EMC Isilon OneFS Devices Detection (FTP)");

  script_tag(name:"summary", value:"Detection of EMC Isilon OneFS devices

This script performs FTP based detection of EMC Isilon OneFS devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/emc/isilon_onefs/detected");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

if (!banner || "Isilon OneFS" >!< banner)
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "Isilon OneFS v([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "emc_isilon_onefs/version", value: version);
}

set_kb_item(name: "emc_isilon_onefs/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:emc:isilon_onefs:");
if (!cpe)
  cpe = 'cpe:/o:emc:isilon_onefs';

register_product(cpe: cpe, port: port, service: "ftp");

log_message(data: build_detection_report(app: "EMC Isilon OneFS", version: version, install: port + '/tcp',
                                         cpe: cpe, concluded: banner),
            port: port);

exit(0);