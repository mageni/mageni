###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_browser_detect_lin.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Tor Browser Bundle Version Detection (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812199");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 12:44:53 +0530 (Tue, 28 Nov 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Tor Browser Bundle Version Detection (Linux)");

  ##Tor Browser Bundle is standalone and cannot be installed
  script_tag(name:"summary", value:"Detection of presence of Tor Browser
  Bundle.

  The script logs in via ssh, searches for executable 'tor browser' and gets
  the version from Doc file.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");
include("version_func.inc");

tor_sock = ssh_login_or_reuse_connection();
if(!tor_sock){
  exit(0);
}

##Currently searchings for all files 'versions'
torName = split(ssh_cmd(socket:tor_sock, cmd:"find / -name 'versions'", timeout:60));
foreach binaryName (torName)
{
  if(("TorBrowser" >< binaryName || "tor-browser" >< binaryName) &&
     (binaryName =~ "Docs/Sources/Versions"))
  {
    torVer = get_bin_version(full_prog_name:"cat", version_argv:binaryName,
                          ver_pattern:'TORBROWSER_VERSION=([0-9.]+)', sock:tor_sock);
    if(torVer[1])
    {
      version = torVer[1];
      set_kb_item(name:"TorBrowser/Linux/Ver", value:version);
      register_and_report_cpe( app:"Tor Browser Bundle", ver:version, concluded:version, base:"cpe:/a:tor:tor:", expr:"^([0-9.]+-?([a-z0-9]+)?)", insloc:binaryName );
    }
  }
}
ssh_close_connection();
exit(0);
