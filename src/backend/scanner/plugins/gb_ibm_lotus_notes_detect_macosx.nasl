###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_detect_macosx.nasl 11284 2018-09-07 09:30:56Z cfischer $
#
# IBM Lotus Notes Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803217");
  script_version("$Revision: 11284 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:30:56 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-01-23 15:23:23 +0530 (Wed, 23 Jan 2013)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("IBM Lotus Notes Version Detection (Mac OS X)");


  script_tag(name:"summary", value:"Detects the installed version of IBM Lotus Notes.

The script logs in via ssh, searches for folder 'Lotus Notes.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}


include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

lotusVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Lotus\ Notes.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(lotusVer) || "does not exist" >< lotusVer){
   exit(0);
}

if(lotusVer =~ "FP")
  lotusVer = ereg_replace(pattern:"FP", string:lotusVer, replace:".");

set_kb_item(name: "IBM/LotusNotes/MacOSX/Ver", value:lotusVer);

cpe = build_cpe(value:lotusVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:lotus_notes:");
if(isnull(cpe))
  cpe = "cpe:/a:ibm:lotus_notes";

lotusPath = "/Applications/Lotus Notes.app";
register_product(cpe:cpe, location:lotusPath);

log_message(data: build_detection_report(app: "IBM Lotus Notes",
                                         version:lotusVer,
                                         install:lotusPath,
                                         cpe:cpe,
                                         concluded: lotusVer));
