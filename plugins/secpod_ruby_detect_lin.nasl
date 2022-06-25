###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_detect_lin.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Ruby Version Detection (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900569");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11279 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Ruby Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of Ruby.

The script logs in via ssh, searches for executable 'ruby' and
queries the found executables via command line option '--version'.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Ruby Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

rubyName = find_bin(prog_name:"ruby", sock:sock);
foreach binaryName (rubyName)
{
  rubyVer = get_bin_version(full_prog_name:chomp(binaryName), version_argv:"--version",
                             ver_pattern:"ruby (.*)", sock:sock);
  dump = rubyVer;

  if(rubyVer[1])
  {
    if("patchlevel" >< rubyVer[1])
    {
      rubyVer = eregmatch(pattern:"([0-9.]+).*patchlevel ([0-9]+)", string:rubyVer[1]);
      if(rubyVer[1] != NULL)
      {
        if(rubyVer[2] != NULL){
          rubyVer = rubyVer[1] + ".p" + rubyVer[2];
      }
      else
        rubyVer = rubyVer[1];
      }
    }
    else
    {
      rubyVer = eregmatch(pattern:"([0-9.]+)([a-z][0-9]+)?", string:rubyVer[1]);
      if(rubyVer[1] != NULL)
      {
        if(rubyVer[2] != NULL){
          rubyVer = rubyVer[1] + "." + rubyVer[2];
        }
        else
          rubyVer = rubyVer[1];
      }
    }
    set_kb_item(name:"Ruby/Lin/Ver", value:rubyVer);
    ssh_close_connection();

    cpe = build_cpe(value:rubyVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:ruby-lang:ruby:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    log_message(data:'Detected Ruby version: ' + rubyVer +
        '\nLocation: ' + binaryName +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + dump[max_index(dump)-1]);

  }
}
ssh_close_connection();
