###############################################################################
# OpenVAS Vulnerability Test
# $Id: nmap_nse.nasl 10575 2018-07-23 11:58:05Z cfischer $
#
# Launch Nmap NSE Tests
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810010");
  script_version("$Revision: 10575 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-23 13:58:05 +0200 (Mon, 23 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 12:08:05 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Launch Nmap NSE Tests");
  script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_dependencies("toolcheck.nasl");
  script_add_preference(name:"Launch Nmap NSE Tests", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This script controls the execution of Nmap NSE Tests");

  exit(0);
}

launch_nmap_nse = script_get_preference("Launch Nmap NSE Tests");
if (launch_nmap_nse == "yes") {
  set_kb_item(name: "Tools/Launch/nmap_nse", value: TRUE);
}
