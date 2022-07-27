###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tnftpd_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# tnftpd Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901005");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("tnftpd Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/tnftpd/detected");

  script_tag(name:"summary", value:"Detection of tnftpd.

  This script finds the running tnftpd Version and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

if(banner && "tnftpd" >< banner) {

  version = "unknown";

  ntftpVer = eregmatch(pattern: "tnftpd ([0-9]+)", string: banner);

  if (!isnull(ntftpVer[1])) {
    version = ntftpVer[1];
    set_kb_item(name: "tnftpd/Ver", value: version);
  }

  set_kb_item(name: "tnftpd/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:luke_mewburn:tnftpd:");
  if (!cpe)
    cpe = 'cpe:/a:luke_mewburn:tnftpd';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "ftp");

  log_message(data: build_detection_report(app: "tnftpd", version: version, install: port + '/tcp',
                                           cpe: cpe, concluded: banner),
              port: port);
}

exit(0);