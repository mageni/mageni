###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powershell_core_detect_lin.nasl 11902 2018-10-15 09:26:53Z santu $
#
# PowerShell Version Detection (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812746");
  script_version("$Revision: 11902 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 11:26:53 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-31 10:53:40 +0530 (Wed, 31 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("PowerShell Version Detection (Linux)");

  script_tag(name:"summary", value:"Detects the installed version of PowerShell.

  The script logs in via ssh, searches for executable 'pwsh' and queries the
  found executables via command line option '-v'");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

ps_sock = ssh_login_or_reuse_connection();
if(!ps_sock) exit( 0 );

list = make_list('pwsh-preview', 'pwsh');
foreach pgm (list)
{
  paths = find_bin(prog_name:pgm, sock:ps_sock);
  foreach bin (paths)
  {
    psVer = get_bin_version(full_prog_name:chomp(bin), sock:ps_sock, version_argv:"-v",
                            ver_pattern:"PowerShell v?([0-9a-z.-]+)");

   if(psVer[1])
   {
      ##For preview versions
      psVer = ereg_replace(pattern:"-preview", string:psVer[1], replace:"");

      set_kb_item(name:"PowerShell/Linux/Ver", value:psVer);

      cpe = build_cpe( value:psVer, exp:"^([0-9rc.-]+)", base:"cpe:/a:microsoft:powershell:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:microsoft:powershell";

      register_product( cpe:cpe, location:bin );

      log_message(data:build_detection_report(app:"PowerShell",
                                              version:psVer,
                                              install:bin,
                                              cpe:cpe,
                                              concluded:psVer));
      exit(0);
    }
  }
}
close(ps_sock);
exit(0);
