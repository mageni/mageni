###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_client_detect_macosx.nasl 14305 2019-03-19 09:17:40Z cfischer $
#
# IBM Tivoli Storage Manager Client Version Detection (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811062");
  script_version("$Revision: 14305 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:17:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-06-02 15:14:25 +0530 (Fri, 02 Jun 2017)");
  script_name("IBM Tivoli Storage Manager Client Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  IBM Tivoli Storage Manager Client.

  The script logs in via ssh, searches for folder 'Tivoli Storage Manager.app'
  and queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
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

ibmVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Tivoli\ Storage\ Manager/Tivoli\ Storage\ Manager.app/Contents/" +
             "Info CFBundleShortVersionString"));
if(!ibmVer || "does not exist" >< ibmVer)
{
  ibmVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "IBM\ Spectrum\ Protect/IBM\ Spectrum\ Protect.app/Contents/" +
             "Info CFBundleShortVersionString"));
}
close(sock);

if(isnull(ibmVer) || "does not exist" >< ibmVer){
  exit(0);
}

set_kb_item(name: "IBM/TSM/Client/MacOSX", value:ibmVer);

cpe = build_cpe(value:ibmVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_storage_manager:");
if(isnull(cpe))
  cpe = "cpe:/a:ibm:tivoli_storage_manager";

ibmPath = "/Applications/Tivoli Storage Manager/Tivoli Storage Manager.app";
register_product(cpe:cpe, location:ibmPath);

log_message(data: build_detection_report(app: "IBM Tivoli Storage Manager",
                                         version:ibmVer,
                                         install:ibmPath,
                                         cpe:cpe,
                                         concluded: ibmVer));
exit(0);
