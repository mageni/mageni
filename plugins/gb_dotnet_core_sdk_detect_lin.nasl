# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.815001");
  script_version("2019-04-25T10:19:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-25 10:19:44 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-13 08:37:41 +0530 (Wed, 13 Mar 2019)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name(".NET Core SDK Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of
  .NET Core SDK.

  The script logs in via ssh, searches for executable 'dotnet' and queries
  the found executables via command line option '--info'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

dot_sock = ssh_login_or_reuse_connection();
if(!dot_sock) exit( 0 );

paths = find_bin(prog_name:"dotnet", sock:dot_sock);
foreach bin (paths)
{
  dotnetop = ssh_cmd( socket:dot_sock, cmd:chomp(bin) + " --info", timeout:60 );
  sdkname = eregmatch(pattern:"No SDKs were found", string:dotnetop);
  if(sdkname){
    exit(0);
  }

  sdkVer = eregmatch(pattern:"Version:   ([0-9.]+)", string:dotnetop);
  if(!sdkVer[1])
  {
    sdkVer = eregmatch(pattern:"Base Path:.*sdk/([0-9.]+)", string:dotnetop);
    if(!sdkVer[1]){
      sdkVer = get_bin_version(full_prog_name:chomp(bin), sock:dot_sock, version_argv:"--version",
                               ver_pattern:"([0-9.]+)");
    }
  }

  if(sdkVer[1])
  {
    set_kb_item(name:"dotnet/core/sdk/Linux/Ver", value:sdkVer[1]);
    cpe = build_cpe(value:sdkVer[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:.net_core_sdk:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:microsoft:.net_core_sdk";

    register_and_report_cpe(app:".NET Core SDK",
                            ver:sdkVer[1],
                            base:"cpe:/a:microsoft:.net_core_sdk:",
                            expr:"^([0-9.]+)",
                            insloc:bin,
                            concluded:sdkVer[1]);
    close(dot_sock);
    exit(0);
  }
}

close(dot_sock);
exit(0);
