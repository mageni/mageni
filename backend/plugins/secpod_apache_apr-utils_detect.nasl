##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_apr-utils_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Apache APR-Utils Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# Updated to Detect Zero Series Versions
#  - By Antu Sanadi <santu@secpod.com> On 2009-08-14
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
  script_oid("1.3.6.1.4.1.25623.1.0.900571");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10891 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache APR-Utils Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script retrieves the version of Apache APR-Utils
  and saves the result in KB.");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Apache APR-Utils Version Detection";

util_sock = ssh_login_or_reuse_connection();
if(!util_sock){
  exit(0);
}

foreach path (make_list("apu-config" ,"apu-1-config"))
{
  getPath = find_bin(prog_name:path, sock:util_sock);

  foreach binaryFile (getPath)
  {
    utilsVer = get_bin_version(full_prog_name:chomp(binaryFile), sock:util_sock,
                               version_argv:"--version", ver_pattern:"[0-9.]+");

    if(utilsVer[0] != NULL){
      set_kb_item(name:"Apache/APR_or_Utils/Installed", value:TRUE);
      set_kb_item(name:"Apache/APR-Utils/Ver", value:utilsVer[0]);
      log_message(data:"Apache APR-Utils version " + utilsVer[0] +
          " running at location " + binaryFile + " was detected on the host");

      cpe = build_cpe(value:utilsVer[0], exp:"^([0-9.]+)", base:"cpe:/a:apache:apr-util:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

    }
  }
}
ssh_close_connection();
