###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpdmin_detect.nasl 13506 2019-02-06 14:18:08Z cfischer $
#
# Ftpdmin Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100131");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13506 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 15:18:08 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Ftpdmin Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ftpdmin/detected");

  script_xref(name:"URL", value:"http://www.sentex.net/~mwandel/ftpdmin/");

  script_tag(name:"summary", value:"Detection of Ftpdmin.

  Ftpdmin is running at this port. Ftpdmin is a minimal Windows FTP server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_ftp_port(default:21);
banner = get_ftp_banner(port:port);

if(banner && "Minftpd" >< banner) {

  vers = "unknown";

  syst = get_ftp_cmd_banner(port:port, cmd:"SYST");
  version = eregmatch(pattern:"^215.*ftpdmin v\. ([0-9.]+)", string:syst);
  if(!isnull(version[1]))
    vers = version[1];

  set_kb_item(name:"ftpdmin/Ver", value:vers);
  set_kb_item(name:"ftpdmin/installed", value:TRUE);

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ftpdmin:ftpdmin:");
  if (!cpe)
    cpe = 'cpe:/a:ftpdmin:ftpdmin';

  register_product(cpe:cpe, location:port + '/tcp', port:port, service:"ftp");

  log_message(data:build_detection_report(app:"Ftpdmin", version:vers, install:port + '/tcp',
                                          cpe:cpe, concluded:version[0]),
              port:port);
}

exit(0);