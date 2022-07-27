##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_virtualbox_detect_lin.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Oracle VirtualBox Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901051");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Oracle VirtualBox Version Detection (Linux)");

  script_tag(name:"summary", value:"Detection of installed versions of Sun/Oracle VirtualBox,
a hypervisor tool, on Linux systems.

The script logs in via ssh, searches for executables of VirtualBox and
queries the found executables via command line option '--version'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

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

getPath = find_bin(prog_name:"VBoxManage", sock:sock);
foreach executableFile (getPath)
{
  vbVer = get_bin_version(full_prog_name:chomp(executableFile), sock:sock,
                          version_argv:"--version",
                          ver_pattern:"([0-9.]+([a-z0-9]+)?)");
  if(vbVer[1] != NULL)
  {
    Ver = ereg_replace(pattern:"([a-z])", string:vbVer[1], replace:".");
    if(Ver){
      set_kb_item(name:"Sun/VirtualBox/Lin/Ver", value:Ver);
      if(version_is_less(version:Ver, test_version:"3.2.0"))
      {
        register_and_report_cpe(app:"Oracle/Sun Virtual Box", ver:Ver, concluded:Ver,
                                base:"cpe:/a:sun:virtualbox:", expr:"^(3\..*)", insloc:executableFile);
        register_and_report_cpe(app:"Oracle/Sun Virtual Box", ver:Ver, concluded:Ver,
                                base:"cpe:/a:sun:xvm_virtualbox:", expr:"^([0-2]\..*)", insloc:executableFile);
      }
      else
      {
        register_and_report_cpe(app:"Oracle/Sun Virtual Box", ver:Ver, concluded:Ver,
                                base:"cpe:/a:oracle:vm_virtualbox:", expr:"^([3-9]\..*)", insloc:executableFile);
      }
    }
  }
}

ssh_close_connection();
