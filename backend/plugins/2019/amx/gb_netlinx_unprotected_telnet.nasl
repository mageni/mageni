# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114080");
  script_version("$Revision: 14176 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:29:33 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-08 13:36:06 +0100 (Fri, 08 Mar 2019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("NetLinx Controller Unprotected Telnet Access");
  script_dependencies("gb_netlinx_telnet_detect.nasl");
  script_mandatory_keys("netlinx/telnet/unprotected");

  script_tag(name:"summary", value:"The NetLinx Controller is accessible via an unprotected telnet connection.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to configure and control the device.");

  script_tag(name:"solution", value:"Disable the telnet access or protect it via a strong password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

CPE = "cpe:/h:amx:netlinx_controller";

if(!port = get_app_port(cpe: CPE)) exit(0);
if(!get_app_location(cpe: CPE, port: port)) exit(0); # nb: Unused but added to have a reference to the Detection-NVT

if(get_kb_item("netlinx/telnet/" + port + "/unprotected")) {
  report = "The Telnet access of this NetLinx Controller on port " + port + " is unprotected.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
