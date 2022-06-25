###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_asterisk_detect.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# Asterisk Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Updated to Set KB for Product Installation
#  - By Sharath S <sharaths@secpod.com> On 2009-08-28
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
  script_oid("1.3.6.1.4.1.25623.1.0.900811");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Asterisk Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"Detection of Asterisk

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("cpe.inc");
include("host_details.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner(port:port, proto:proto);

if(banner && ("Asterisk PBX" >< banner || "FPBX-" >< banner)) {

  version = "unknown";

  asteriskVer = eregmatch(pattern:"Asterisk PBX (certified/)?([0-9.]+(.?[a-z0-9]+)?)", string:banner);

  if( ! isnull( asteriskVer[2] ) ) {
    version = ereg_replace(pattern:"-", replace:".", string:asteriskVer[2]);
    set_kb_item(name:"Asterisk-PBX/Ver", value:version);
  } else {
    vers = eregmatch( pattern:'FPBX-[0-9.]+\\(([0-9.]+[^)]+)\\)', string:banner );
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name:"Asterisk-PBX/Ver", value:version);
    }
  }

  set_kb_item(name:"Asterisk-PBX/Installed", value:TRUE);
  cpe = build_cpe(value:version, exp:"^([0-9.]+\.[0-9]+)\.?((rc[0-9]+)|(cert[1-9]))?", base:"cpe:/a:digium:asterisk:");
  if(isnull(cpe))
    cpe = 'cpe:/a:digium:asterisk';

  location = port + "/" + proto;

  register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );
  log_message(data: build_detection_report(app:"Asterisk-PBX", version:version, install:location, cpe:cpe, concluded:banner),
                                             port:port, proto:proto);
}

exit(0);