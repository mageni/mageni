###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openjdk_detect.nasl 13959 2019-03-01 11:27:26Z cfischer $
#
# Sun/Oracle OpenJDK Version Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900334");
  script_version("$Revision: 13959 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 12:27:26 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun/Oracle OpenJDK Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of OpenJDK and sets
  the reuslt in KB.");

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

paths = find_bin(prog_name:"java", sock:sock);
foreach binName (paths) {

  binName = chomp(binName);

  if(!binName)
    continue;

  # There are differences in the output of the version between OpenJDK versions, we need to differ between both here:
  #
  # java version "1.7.0_171"
  # OpenJDK Runtime Environment (IcedTea 2.6.13) (7u171-2.6.13-1~deb7u1)
  # OpenJDK 64-Bit Server VM (build 24.171-b02, mixed mode)
  #
  # vs.
  #
  # openjdk version "11.0.2" 2019-01-15
  # OpenJDK Runtime Environment (build 11.0.2+9-Debian-3)
  # OpenJDK 64-Bit Server VM (build 11.0.2+9-Debian-3, mixed mode, sharing)
  #
  # vs.
  #
  # openjdk version "1.8.0_131"
  # OpenJDK Runtime Environment (IcedTea 3.4.0) (suse-10.10.3-x86_64)
  # OpenJDK 64-Bit Server VM (build 25.131-b11, mixed mode)

  ver = get_bin_version(full_prog_name:binName, version_argv:"-version", ver_pattern:'(openjdk|java) version "([0-9]\\.[0-9]\\.[0-9._]+)-?([b0-9]+)?.+', sock:sock);
  if("OpenJDK" >< ver) {

    jvVer    = ereg_replace( pattern:"_|-", string:ver, replace:"." );
    javaVer1 = eregmatch( pattern:"([0-9]+\.[0-9]+\.[0-9]+)(\.([0-9]+))?", string:jvVer );
    if( javaVer1[1] && javaVer1[3] ) {
      jvVer = javaVer1[1] + ":update_" + javaVer1[3];
    } else if( javaVer1[1] ) {
      jvVer = javaVer1[1];
    } else {
      jvVer = eregmatch( pattern:"([0-9.]+)", string:javaVer[1] );
      jvVer = jvVer[1];
    }

    if(jvVer) {
      if(version_is_less(version:jvVer, test_version:"1.4.2.38" )||
         version_in_range(version:jvVer, test_version:"1.5", test_version2:"1.5.0.33" )||
         version_in_range(version:jvVer, test_version:"1.6", test_version2:"1.6.0.18" ) )
      {
        app_name = "Sun OpenJDK";
        base_cpe = "cpe:/a:sun:openjdk:";
      } else {
        app_name = "Oracle OpenJDK";
        base_cpe = "cpe:/a:oracle:openjdk:";
      }

      set_kb_item(name:"openjdk/detected", value:TRUE);

      register_and_report_cpe( app:app_name, ver:jvVer, concluded:ver[0], base:base_cpe, expr:"^([:a-z0-9._]+)", insloc:binName, regPort:0, regService:"ssh-login" );
    }
  }
}

ssh_close_connection();
exit(0);