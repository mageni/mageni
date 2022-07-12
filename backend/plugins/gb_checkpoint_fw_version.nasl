###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_checkpoint_fw_version.nasl 10902 2018-08-10 14:20:55Z cfischer $
#
# Check Point Firewall Version Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140454");
  script_version("$Revision: 10902 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-26 10:52:10 +0700 (Thu, 26 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Check Point Firewall Version Detection");

  script_tag(name:"summary", value:"This Script consolidate the via SSH/HTTP detected version of the Check Point
Firewall.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl", "gb_checkpoint_fw_web_detect.nasl");
  script_mandatory_keys("checkpoint_fw/detected");

  script_xref(name:"URL", value:"https://www.checkpoint.com/");

  exit(0);
}

include("host_details.inc");

source = "ssh";

if (!version = get_kb_item("checkpoint_fw/" + source + "/version")) {
  source = "http";
  if (!version = get_kb_item("checkpoint_fw/" + source + "/version"))
    exit(0);
  else {
    register_and_report_os(os: "Check Point Gaia", cpe: "cpe:/o:checkpoint:gaia_os", banner_type: toupper(source),
                           desc: "Check Point Firewall Version Detection", runs_key: "unixoide");
  }
}

set_kb_item(name: "checkpoint_fw/version", value: version);
set_kb_item(name: "checkpoint_fw/version_source", value: source);

cpe = 'cpe:/o:checkpoint:gaia_os:' + tolower(version);

register_product(cpe: cpe, location: source);

exit(0);
