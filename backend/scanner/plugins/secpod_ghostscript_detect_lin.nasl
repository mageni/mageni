###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ghostscript_detect_lin.nasl 13267 2019-01-24 12:56:48Z cfischer $
#
# Ghostscript Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900541");
  script_version("$Revision: 13267 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 13:56:48 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Ghostscript Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Ghostscript.

  The script logs in via ssh, searches for executable 'gs' and
  queries the found executables via command line option '--help'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

gsName = find_file(file_name:"gs", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
foreach executableFile(gsName)
{
  executableFile = chomp(executableFile);
  if(!executableFile) continue;
  gsVer = get_bin_version(full_prog_name:executableFile, version_argv:"--help", ver_pattern:"Ghostscript ([0-9]\.[0-9.]+)", sock:sock);

  if(!isnull(gsVer[1]))
  {
    resp = gsVer[max_index(gsVer)-1];
    if("Ghostscript" >< resp && "Artifex Software," >< resp)
    {
      set_kb_item(name:"Ghostscript/Linux/Ver", value:gsVer[1]);

      cpe = build_cpe(value:gsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ghostscript:ghostscript:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:executableFile);

      log_message(data:'Detected Ghostscript version: ' + gsVer[1] +
          '\nLocation: ' + executableFile +
          '\nCPE: '+ cpe +
          '\n\nConcluded from version identification result:\n' + gsVer[1]);
    }
  }
}

ssh_close_connection();