# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810933");
  script_version("2023-02-27T10:17:28+0000");
  script_tag(name:"last_modification", value:"2023-02-27 10:17:28 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2017-04-20 13:57:40 +0530 (Thu, 20 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axis Devices Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/axis/device/detected");

  script_tag(name:"summary", value:"FTP based detection of Axis devices.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);

# 220 AXIS Q3517 Fixed Dome Network Camera 8.40.1.1 (2018) ready.
# 220 AXIS Q1765-LE Network Camera 5.55.2.1 (2014) ready.
# 220 AXIS M2036-LE Bullet Camera 10.12.114 (2022) ready.
# 220 AXIS 243SA Video Server 4.45 (Dec 14 2007) ready.
# 220 AXIS 2400 Video Server 2.34 Apr 11 2003 ready.
# 220 AXIS A8105-E Network Video Door Station 1.65.6 (2022) ready.
# 220 AXIS 206M Network Camera 4.40.1 (Jul 17 2006) ready.
# nb: Keep in sync with the banner used in gb_ftp_os_detection.nasl and ftpserver_detect_type_nd_version.nasl
if (!banner || banner !~ "220[- ](AXIS|Axis).+(Camera|Video Server|Station)")
  exit(0);

version = "unknown";
model = "unknown";
full_name = "unknown";

# nb: See examples above
mod = eregmatch(pattern:"220 ((AXIS|Axis) ([^ ]+).+(Camera|Video Server|Station)) ", string:banner);
if (!isnull(mod[3]))
  model = mod[3];

if (!isnull(mod[1]))
  full_name = mod[1];

# nb: See examples above
vers = eregmatch(pattern:"(Camera|Video Server|Station) ([0-9.]+)", string:banner);
if (!isnull(vers[2]))
  version = vers[2];

set_kb_item(name:"axis/device/detected", value:TRUE);
set_kb_item(name:"axis/device/ftp/detected", value:TRUE);
set_kb_item(name:"axis/device/ftp/port", value:port);

set_kb_item(name:"axis/device/ftp/" + port + "/model", value:model);
set_kb_item(name:"axis/device/ftp/" + port + "/modelName", value:full_name);
set_kb_item(name:"axis/device/ftp/" + port + "/version", value:version);
set_kb_item(name:"axis/device/ftp/" + port + "/concluded", value:banner);

exit(0);
