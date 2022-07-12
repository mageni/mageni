###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bisonware_bisonftp_server_detect.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# BisonWare BisonFTP Server Version Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805752");
  script_version("$Revision: 13497 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-09-28 17:53:15 +0530 (Mon, 28 Sep 2015)");
  script_name("BisonWare BisonFTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/bisonware/bisonftp/detected");

  script_tag(name:"summary", value:"This script detects the installed
  version of BisonWare BisonFTP Server and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);

if(banner && "BisonWare BisonFTP server" >< banner){

  ftpVer = "unknown";

  ver = eregmatch(pattern:"product V([0-9.]+)", string:banner);
  if(ver[1]) ftpVer = ver[1];

  set_kb_item(name:"BisonWare/Ftp/Installed", value:TRUE);

  cpe = build_cpe(value:ftpVer, exp:"^([0-9.]+)", base:"cpe:/a:bisonware:bison_ftp_server:");
  if(!cpe)
    cpe = "cpe:/a:bisonware:bison_ftp_server";

  register_product(cpe:cpe, location:ftpPort + "/tcp", port:ftpPort, service:"ftp");

  log_message(data:build_detection_report(app:"BisonWare BisonFTP Server",
                                          version:ftpVer,
                                          install:ftpPort + "/tcp",
                                          cpe:cpe,
                                          concluded:banner),
                                          port:ftpPort);
}

exit(0);
