###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grandstream_gxp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Grandstream GXP Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103594");
  script_version("$Revision: 11885 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-26 11:15:41 +0200 (Fri, 26 Oct 2012)");
  script_name("Grandstream GXP Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Grandstream_GXP/banner");

  script_tag(name:"summary", value:"Detection of Grandstream GXP IP Phone.

The script sends a connection request to the server and attempts to
extract the version number from the reply.");
  exit(0);
}

include("http_func.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Server: Grandstream GXP" >!< banner)exit(0);

version_typ = eregmatch(pattern:"Server: Grandstream GXP([^ ]+) ([0-9.]+)", string:banner);

typ = 'unknown';
ver = 'unknown';

if(!isnull(version_typ[1])) typ = version_typ[1];
if(!isnull(version_typ[2])) ver = version_typ[2];

cpe_str = 'cpe:/h:grandstream:gxp-' + typ + ':';
cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:cpe_str);
if(isnull(cpe))
  cpe = cpe_str;

set_kb_item(name:"Grandstream/typ", value:typ);

register_product(cpe:cpe, location:port + '/tcp', port:port);

log_message(data: build_detection_report(app:"Grandstream GXP" + typ + " IP Phone", version:ver, install:port + '/tcp', cpe:cpe, concluded: banner),
            port:port);

exit(0);
