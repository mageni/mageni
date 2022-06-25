###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openjdk_detect.nasl 5159 2017-02-01 17:52:54Z cfi $
#
# OpenJDK Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_summary = "This script detects the installed version of OpenJDK and sets
  the reuslt in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.315149");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5159 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-01 18:52:54 +0100 (Wed, 01 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenJDK Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_DESC = "OpenJDK Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"java", sock:sock);
foreach binName (paths)
{
  if( chomp(binName) == "" ) continue;
  ver = get_bin_version(full_prog_name:chomp(binName), version_argv:"-version",
                        ver_pattern:"OpenJDK.*([0-9]\.[0-9]\.[0-9._]+)-?([b0-9]+)?",
                        sock:sock);

  dump = ver;

  if("OpenJDK" >< ver)
  {
    if((ver[1] && ver[2]) != NULL){
      ver = ver[1] + "." + ver[2];
    }
    else{
      ver = ver[1];
    }

    if(ver != NULL)
    {
      set_kb_item(name:"OpenJDK/Ver", value:ver);
      ssh_close_connection();

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:sun:openjdk:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      log_message(data:'Detected OpenJDK version: ' + ver +
        '\nLocation: ' + binName +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + dump[max_index(dump)-1]);

      exit(0);
    }
  }
}
ssh_close_connection();
