###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cyrus_sasllib_detect.nasl 14002 2019-03-05 15:54:26Z cfischer $
#
# Cyrus SASL Library Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.900659");
  script_version("$Revision: 14002 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 16:54:26 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-28 07:14:08 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyrus SASL Library Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Cyrus SASL Library and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

paths = find_bin(prog_name:"sasldblistusers2", sock:sock);
foreach saslbin (paths) {

  saslbin = chomp(saslbin);
  if(!saslbin)
    continue;

  saslVer = get_bin_version(full_prog_name:saslbin, sock:sock, version_argv:"-v", ver_pattern:"version ([0-9.]+)");
  if(saslVer[1])  {

    set_kb_item(name:"Cyrus/SASL/Ver", value:saslVer[1]);
    set_kb_item(name:"cyrus/sasl/dected", value:TRUE);

    register_and_report_cpe(app:"Cyrus SASL Library", ver:saslVer[1], base:"cpe:/a:cmu:cyrus-sasl:", expr:"^([0-9.]+)", regPort:0, insloc:saslbin, concluded:saslVer[max_index(saslVer)-1], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit(0);