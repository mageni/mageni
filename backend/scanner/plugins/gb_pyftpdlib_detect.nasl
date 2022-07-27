###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# pyftpdlib Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801612");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("pyftpdlib Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/pyftpdlib/detected");

  script_tag(name:"summary", value:"Detection of pyftpdlib

  This script finds the version of running FTPServer.py in pyftpdlib and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);

if(banner && "pyftpd" >< tolower(banner)){

  version = "unknown";

  ver = eregmatch(pattern:"(Pyftpd|pyftpdlib) ([0-9.]+)", string:banner, icase:TRUE);
  if(!isnull(ver[2])) {
    version = ver[2];
    set_kb_item(name:"pyftpdlib/Ver", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:g.rodola:pyftpdlib:");
  if (!cpe)
    cpe = 'cpe:/a:g.rodola:pyftpdlib';

  register_product(cpe:cpe, location:port + '/tcp', port:port, service:"ftp");

  log_message(data:build_detection_report(app:"pyftpdlib FTP Server", version:version, install:port + '/tcp',
                                          cpe:cpe, concluded:banner),
              port:port);
}

exit(0);