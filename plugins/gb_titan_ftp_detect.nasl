###############################################################################
# OpenVAS Vulnerability Test
#
# Titan FTP Server Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800236");
  script_version("2019-04-09T13:55:37+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-09 13:55:37 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_name("Titan FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/titan/ftp/detected");

  script_tag(name:"summary", value:"Detection of Titan FTP Server

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);

if (banner && "220 Titan FTP Server " >< banner) {
  version = "unknown";
  install = port + "/tcp";

  titanVer = eregmatch(pattern:"Titan FTP Server ([0-9.]+)", string:banner);
  if (!isnull(titanVer[1]))
    version = titanVer[1];

  set_kb_item(name:"TitanFTP/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:southrivertech:titan_ftp_server:");
  if (!cpe)
    cpe = "cpe:/a:southrivertech:titan_ftp_server";

  register_product(cpe:cpe, location:install, port:port, service:"ftp");

  log_message(data:build_detection_report(app:"Titan FTP Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:banner),
              port:port);
}

exit(0);