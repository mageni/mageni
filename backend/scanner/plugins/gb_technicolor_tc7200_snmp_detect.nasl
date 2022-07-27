###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_technicolor_tc7200_snmp_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# Technicolor TC7200 Modem/Router Detection (SNMP)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811655");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 12:12:54 +0530 (Fri, 08 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Technicolor TC7200 Modem/Router Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"Detection of Technicolor Modem/Router.
  This script performs SNMP based detection of Technicolor Modem/Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if("VENDOR: Technicolor" >< sysdesc && "TC7200" >< sysdesc)
{
  model = "unknown";
  version = "unknown";

  mod = eregmatch(pattern:"MODEL: ([0-9A-Z]+).", string:sysdesc);
  if(!isnull(mod[1])){
    model = mod[1];
    set_kb_item(name:"technicolor/model/version", value:model);
  }

  firmvers = eregmatch(pattern:"SW_REV: ([0-9A-Z.]+);", string:sysdesc);
  if(!isnull(firmvers[1])){
    version = firmvers[1];
    set_kb_item(name:"technicolor/firmware/version", value:version);
  }

  set_kb_item(name:"technicolor/detected", value:TRUE);

  oscpe = build_cpe( value:firmvers[1], exp:"^([0-9.]+)", base:"cpe:/o:technicolor:tc7200_firmware:" );
  if( ! oscpe )
    oscpe = "cpe:/o:technicolor:tc7200_firmware";

  hwcpe = "cpe:/h:technicolor:tc7200_firmware:" + tolower(version);
  register_product( cpe:hwcpe, port:port, location:port + "/udp", service:"snmp", proto:"udp" );
  register_product( cpe:oscpe, port:port, location:port + "/udp", service:"snmp", proto:"udp" );

  register_and_report_os(cpe:oscpe, banner_type:"SNMP sysdesc", port:port, proto:"udp",
                         banner:sysdesc, desc:"Technicolor TC7200 Modem/Router Detection (SNMP)",
                         runs_key:"unixoide");

  log_message(data: build_detection_report(app:"Technicolor TC7200",
                                           version:version,
                                           install:port + "/udp",
                                           cpe:oscpe,
                                           concluded:sysdesc),
                                           port:port,
                                           proto:"udp");
  exit(0);
}
exit(0);
