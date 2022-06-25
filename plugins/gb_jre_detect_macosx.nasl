###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jre_detect_macosx.nasl 11283 2018-09-07 09:28:09Z cfischer $
#
# Java Runtime Environment (JRE) Version Detection (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.802736");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11283 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:28:09 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-06 18:27:52 +0530 (Fri, 06 Apr 2012)");

  script_name("Java Runtime Environment (JRE) Version Detection (Mac OS X)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_family("Product detection");
  script_mandatory_keys("ssh/login/osx_name");
  script_tag(name:"summary", value:"Detects the installed version of Java.

The script logs in via ssh, and gets the version via command line option
'java -version'.");
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

if (!get_kb_item("ssh/login/osx_name"))
{
  close(sock);
  exit(0);
}

javaVer = chomp(ssh_cmd(socket:sock, cmd:"java -version"));

close(sock);

if(isnull(javaVer) || "command not found" >< javaVer){
  exit(0);
}

javaVer = eregmatch(pattern:'java version "([0-9.]+_?[0-9]+)', string:javaVer);
if(javaVer[1])
{
  cpe = build_cpe(value:javaVer[1], exp:"^([0-9.]+_?[0-9]+)", base:"cpe:/a:oracle:jre:");
  if(!isnull(cpe))
    register_product(cpe:cpe, location:'/System/Library/Java/JavaVirtualMachines');
  else
    cpe = "Failed";


  set_kb_item(name: "JRE/MacOSX/Version", value:javaVer[1]);
  log_message(data:'Detected Java version: ' + javaVer[1] +
                   '\nLocation: /System/Library/Java/JavaVirtualMachines' +
                   '\nCPE: '+ cpe +
                   '\n\nConcluded from version identification result:\n' +
                   "Java " + javaVer[1]);
}
