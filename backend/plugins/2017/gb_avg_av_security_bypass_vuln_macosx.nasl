###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_av_security_bypass_vuln_macosx.nasl 11545 2018-09-21 20:43:34Z cfischer $
#
# AVG AntiVirus Version Detection (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811525");
  script_version("$Revision: 11545 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 22:43:34 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-07-17 14:59:13 +0530 (Mon, 17 Jul 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("AVG AntiVirus Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of
  AVG AntiVirus on MAC OS X.

  The script logs in via ssh, searches for folder 'AVGAntivirus.app' and
  queries the related 'info.plist' file for string 'CFBundleVersion'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  exit(0);
}

include("cpe.inc");
include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

name = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
            "AVGAntivirus.app/Contents/Info " +
            "CFBundleName"));

if("AVGAntiVirus" >< name)
{
  installVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
              "AVGAntivirus.app/Contents/Info " +
              "CFBundleVersion"));

  close(sock);

  if(isnull(installVer) || "does not exist" >< installVer){
    exit(0);
  }

  set_kb_item(name: "AVGAntiVirus/MacOSX/Version", value:installVer);

  ## created new cpe
  cpe = build_cpe(value:installVer, exp:"^([0-9.]+)", base:"cpe:/a:avg:avg_anti-virus:");
  if(isnull(cpe))
    cpe='cpe:/a:avg:avg_anti-virus:';

  register_product(cpe:cpe, location:'/Applications');

  log_message(data: build_detection_report(app: "AVGAntiVirus",
                                           version: installVer,
                                           install: "/Applications",
                                           cpe: cpe,
                                           concluded: installVer));
  exit(0);
}
