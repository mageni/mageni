# OpenVAS Vulnerability Test
# $Id: ws_ftp_client_weak_stored_pass.nasl 12663 2018-12-05 12:22:06Z jschulte $
# Description: WS_FTP client weak stored password
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
# Ref: Bernardo Quintero of Hispasec <bernardo@hispasec.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14597");
  script_version("$Revision: 12663 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 13:22:06 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(547);
  script_cve_id("CVE-1999-1078");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WS_FTP client weak stored password");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("secpod_ws_ftp_client_detect.nasl");
  script_mandatory_keys("Ipswitch/WS_FTP_Pro/Client/Ver");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the newest version of the WS_FTP client");
  script_tag(name:"summary", value:"The remote host has a version of the WS_FTP client which use a weak
  encryption method to store site password.");
  script_xref(name:"URL", value:"http://www.ipswitch.com/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list("cpe:/a:ipswitch:ws_ftp:x64", "cpe:/a:ipswitch:ws_ftp" );
if(!infos = get_app_version_and_location( cpe:cpe, exit_no_version: TRUE)) exit(0);

ftpVer = infos["version"];
loc = infos["location"];

if(version_is_less_equal(version:ftpVer, test_version:"2007.0.0.2")){
  report = report_fixed_ver(installed_version:ftpVer, fixed_version:"12.6", install_path:loc);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
