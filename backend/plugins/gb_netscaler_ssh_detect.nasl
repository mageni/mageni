###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netscaler_ssh_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Citrix Netscaler Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140667");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Citrix Netscaler Detection (SSH)");

  script_tag(name:"summary", value:"Detection of Citrix Netscaler

This script performs SSH based detection of Citrix NetScaler.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("citrix_netscaler/found");

  script_xref(name:"URL", value:"https://www.citrix.com/products/netscaler-adc/");

  exit(0);
}

if (!system = get_kb_item("citrix_netscaler/system"))
  exit(0);

port = get_kb_item("citrix_netscaler/ssh/port");

set_kb_item(name: "citrix_netscaler/detected", value: TRUE);
set_kb_item(name: "citrix_netscaler/ssh/detected", value: TRUE);

version = "unknown";

# NetScaler NS11.0: Build 62.10.nc, Date: Aug 8 2015, 23:00:46
vers = eregmatch(pattern: "NetScaler NS([0-9\.]+): (Build (([0-9\.]+))(.e)?.nc)?", string: system);
if (!isnull(vers[1])) {
  if (!isnull(vers[3]))
    version = vers[1] + "." + vers[3];
  else
    version = vers[1];

  # Enhanced Build
  if (!isnull(vers[5]))
    set_kb_item(name: "citrix_netscaler/enhanced_build", value: TRUE);

  set_kb_item(name: "citrix_netscaler/ssh/" + port + "/version", value: version);
  set_kb_item(name: "citrix_netscaler/ssh/" + port + "/concluded", value: system);
}

exit(0);
