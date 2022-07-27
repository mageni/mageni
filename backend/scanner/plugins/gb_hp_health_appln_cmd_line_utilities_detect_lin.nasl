###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_health_appln_cmd_line_utilities_detect_lin.nasl 10925 2018-08-11 08:37:51Z cfischer $
#
# HP System Health Application and Command Line Utilities Version Detection (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802770");
  script_version("$Revision: 10925 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 10:37:51 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-05-08 13:05:57 +0530 (Tue, 08 May 2012)");
  script_name("HP System Health Application and Command Line Utilities Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of HP System Health
  Application and Command Line Utilities.

  The script logs in via ssh, searches for HP System Health Application and
  Command Line Utilities from the list of installed rpm packages and gets
  the version");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

rpms = get_kb_item("ssh/login/rpms");
if(isnull(rpms) || rpms !~ "hp-health") exit(0);

version = eregmatch(pattern:"hp-health.?([0-9.]+)", string:rpms);
if(!version[1]) exit(0);

path = "/opt/hp/hp-health/";

set_kb_item(name:"HP/Health/CLU", value:version[1]);
cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:hp:system_health_application_and_command_line_utilities:");

if(!isnull(cpe))
  register_product(cpe:cpe, location:path);

  log_message(data:build_detection_report(app:"HP System Health Application and Command Line Utilities",
                                          version:version[1],
                                          install:path,
                                          cpe:cpe,
                                          concluded:version[1]));
