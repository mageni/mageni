###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_merak_mail_server_detect.nasl 13127 2019-01-17 14:33:33Z cfischer $
#
# Merak Mail Server Web Mail Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800096");
  script_version("$Revision: 13127 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 15:33:33 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-06-02 09:27:25 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Merak Mail Server Web Mail Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IceWarp/banner");
  script_require_ports("Services/www", 80, 32000);

  script_tag(name:"summary", value:"Detection of Merak Mail Server Web Mail.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.

  This NVT has been replaced by gb_icewarp_web_detect.nasl (1.3.6.1.4.1.25623.1.0.140329) and
  gb_icewarp_mail_detect.nasl (1.3.6.1.4.1.25623.1.0.140330).");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

exit(66);