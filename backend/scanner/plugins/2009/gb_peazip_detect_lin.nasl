###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_peazip_detect_lin.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# PeaZIP Version Detection (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script detects the installed version of PeaZIP and sets
  the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.304544");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PeaZIP Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800594";
SCRIPT_DESC = "PeaZIP Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("PeaZip [0-9.]\\+");

# Set KB for PeaZIP
peazipName = find_file(file_name:"peazip", file_path:"/",
                      useregex:TRUE, regexpar:"$", sock:sock);
if(peazipName != NULL)
{
  foreach binaryName (peazipName)
  {
    binaryName = chomp(binaryName);
    if(islocalhost())
    {
      garg[4] = binaryName;
      arg = garg;
    }
    else
    {
      arg = garg[0]+" "+garg[1]+" "+garg[2]+" "+
            raw_string(0x22)+garg[3]+raw_string(0x22)+" "+binaryName;
    }

    peazipVer = get_bin_version(full_prog_name:grep, version_argv:arg, sock:sock,
                               ver_pattern:"([0-9.]+[a-z]?)");
    if(peazipVer[1] != NULL)
    {
      set_kb_item(name:"PeaZIP/Lin/Ver", value:peazipVer[1]);
      log_message(data:"PeaZIP version " + peazipVer[1] + 
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:peazipVer[1], exp:"^([0-9.]+)", base:"cpe:/a:giorgio_tani:peazip:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      break;
    }
  }
}
