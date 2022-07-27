###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_fusion_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# VMware Fusion Version Detection (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902633");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-11-17 17:38:48 +0530 (Thu, 17 Nov 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VMware Fusion Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of VMware Fusion.

The script logs in via ssh, searches for folder 'VMware Fusion.app' and
queries the related 'info.plist' file for string 'CFBundleShortVersionString'
via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

vmfusionVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
                "VMware\ Fusion.app/Contents/Info CFBundleShortVersionString"));
close(sock);

if(isnull(vmfusionVer) || "does not exist" >< vmfusionVer){
  exit(0);
}

set_kb_item(name: "VMware/Fusion/MacOSX/Version", value:vmfusionVer);

cpe = build_cpe(value:vmfusionVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:fusion:");
if(isnull(cpe))
  cpe='cpe:/a:vmware:fusion';

register_product(cpe:cpe, location:"/Applications/VMware Fusion.app");

log_message(data: build_detection_report(app: "VMware Fusion",
                                         version: vmfusionVer,
                                         install: "/Applications/VMware Fusion.app",
                                         cpe: cpe,
                                         concluded: vmfusionVer));
