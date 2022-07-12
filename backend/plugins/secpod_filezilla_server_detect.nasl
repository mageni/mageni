###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_filezilla_server_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# FileZilla Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900518");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FileZilla Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/filezilla/detected");

  script_tag(name:"summary", value:"Detection of FileZilla Server

  This script finds the version of FileZilla Server and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

if("FileZilla Server" >< banner) {

  version = "unknown";

  fzillaVer = eregmatch(pattern: "FileZilla Server version ([0-9a-z.]+)", string: banner);
  if (!isnull(fzillaVer[1])) {
    version = fzillaVer[1];
    set_kb_item(name: "FileZilla/Serv/Ver", value: version);
  }

  set_kb_item(name: "FileZilla/Serv/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+([a-z])?)", base: "cpe:/a:filezilla:filezilla_server:");
  if (!cpe)
    cpe = 'cpe:/a:filezilla:filezilla_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "ftp");

  log_message(data: build_detection_report(app: "FileZilla Server", version: version, install: port + '/tcp',
                                           cpe: cpe, concluded: banner),
              port: port);
}

exit(0);