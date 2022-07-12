# OpenVAS Vulnerability Test
# $Id: robotftp.nasl 13613 2019-02-12 16:12:57Z cfischer $
# Description: RobotFTP DoS
#
# Authors:
# Audun Larsen <larsen@xqus.com>
# Modified by rd to use get_ftp_banner() and be solely banner-based
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12082");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9729);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RobotFTP DoS");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 Audun Larsen");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/robot/ftp/detected");

  script_tag(name:"summary", value:"The remote host seems to be running RobotFTP.

  RobotFTP server has been reported prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The issue presents itself when certain commands are sent to the service,
  before authentication is negotiated.");

  script_tag(name:"affected", value:"The following versions of RobotFTP are vulnerable:

  RobotFTP RobotFTP Server 1.0

  RobotFTP RobotFTP Server 2.0 Beta 1

  RobotFTP RobotFTP Server 2.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default:21);
banner  = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.*RobotFTP", string:banner) )
{
  security_message(port);
  exit(0);
}