###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_cameras_ftp_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Axis Camera Detection (FTP)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810933");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-04-20 13:57:40 +0530 (Thu, 20 Apr 2017)");
  script_name("Axis Camera Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/axis/network_camera/detected");

  script_tag(name:"summary", value:"Detection of Axis Camera.

  This script performs FTP based detection of Axis Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");

axport = get_ftp_port(default:21);
banner = get_ftp_banner(port:axport);
if(!banner || banner !~ "220[- ](AXIS|Axis).*Network Camera")
  exit(0);

set_kb_item(name:"axis/camera/installed", value:TRUE);
version = "unknown";

v = eregmatch(pattern:'Network Camera ([0-9.]+)', string:banner);
if(v[1]){
  version = v[1];
  set_kb_item(name:"axis/camera/version", value:version);
}

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:axis:network_camera:");
if(isnull(cpe)){
  cpe = "cpe:/a:axis:network_camera";
}

m = eregmatch(pattern:'220 (AXIS|Axis) ([A-Z0-9.]+)', string:banner);
if(m[2]){
  model = m[2];
  set_kb_item(name:"axis/camera/model", value:m[2]);
}

register_product(cpe:cpe, location:axport + '/tcp', port:axport, service:"ftp");

log_message(data:build_detection_report(app:"Axis Camera " + model,
                                        version:version,
                                        install:axport + '/tcp',
                                        cpe:cpe,
                                        concluded:banner),
            port:axport);
exit(0);
