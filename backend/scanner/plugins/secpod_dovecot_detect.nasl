###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dovecot_detect.nasl 10450 2018-07-07 09:48:13Z cfischer $
#
# Dovecot Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.901025");
  script_version("$Revision: 10450 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-07 11:48:13 +0200 (Sat, 07 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dovecot Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Dovecot and sets the
  result in KB.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

paths = find_bin( prog_name:"dovecot", sock:sock );
foreach dovecotbin( paths ) {

  dovecotVer = get_bin_version( full_prog_name:chomp( dovecotbin ), sock:sock, version_argv:"--version", ver_pattern:"([0-9.]+)" );

  # e.g. 2.2.27 (c0f36b0)
  if( ! isnull( dovecotVer[1] ) && dovecotVer[1] =~ "^[0-9]" ) {
    set_kb_item( name:"dovecot/detected", value:TRUE );
    set_kb_item( name:"dovecot/ssh-login/detected", value:TRUE );

    # Format used in gb_dovecot_consolidation.nasl is:
    # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
    set_kb_item( name:"dovecot/detection-info", value:"SSH Login#--#ssh-login#--#0#--#" + dovecotbin + "#--#" + dovecotVer[1] + "#--#" + dovecotVer[0] );
  }
}

ssh_close_connection();
exit( 0 );