###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_isc_dhcp_client_detect.nasl 13935 2019-02-28 12:36:38Z cfischer $
#
# ISC DHCP Client Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.900696");
  script_version("$Revision: 13935 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 13:36:38 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ISC DHCP Client Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of ISC DHCP Client.

  The script logs in via ssh, searches for executable 'dhclient' and
  queries the found executables via command line option '--version'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

dhcp_sock = ssh_login_or_reuse_connection();
if(!dhcp_sock)
  exit(0);

paths = find_bin(prog_name:"dhclient", sock:dhcp_sock);
foreach executableFile (paths) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  dhcpVer = get_bin_version(full_prog_name:executableFile, sock:dhcp_sock, version_argv:"--version", ver_pattern:"isc-dhclient-([0-9.]+)(-| )?((alpha|beta|rc|[a-z][0-9])?([0-9]+)?)");
  if(dhcpVer[1]) {

    _ver = eregmatch(string:dhcpVer[0], pattern:"([0-9.]+)(-| )?((alpha|beta|rc|[a-z][0-9])?([0-9]+)?)");
    if(_ver[3]){
      ver = _ver[1] + "." + _ver[3];
    } else {
      ver = _ver[1];
    }

    set_kb_item(name:"ISC/DHCP-Client/Ver", value:ver);
    set_kb_item(name:"isc/dhcp-client/detected", value:TRUE);

    register_and_report_cpe(app:"ISC DHCP Client", ver:ver, base:"cpe:/a:isc:dhcp:", expr:"^([0-9.]+([a-z0-9]+)?)", regPort:0, insloc:executableFile, concluded:dhcpVer[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);