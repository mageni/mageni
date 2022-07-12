##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xine-lib_mult_vuln_aug08_900041.nasl 12767 2018-12-12 08:39:09Z asteins $
# Description: xine-lib Multiple Vulnerabilities (Aug-08)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900041");
  script_version("$Revision: 12767 $");
  script_cve_id("CVE-2008-5236");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 09:39:09 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2008 SecPod");
  script_name("xine-lib Multiple Vulnerabilities (Aug-08)");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31567/");
  script_xref(name:"URL", value:"http://www.ocert.org/analysis/2008-008/analysis.txt");
  script_xref(name:"URL", value:"http://www.linuxfromscratch.org/blfs/view/svn/multimedia/xine-lib.html");

  script_tag(name:"summary", value:"The host has xine-lib installed, which prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to overflow errors that exist in open_ra_file()
  in demux_realaudio.c, parse_block_group() in demux_matroska.c, and
  real_parse_audio_specific_data() in demux_real.c methods.");

  script_tag(name:"affected", value:"xine-lib versions 1.1.15 and prior on Linux (All).");

  script_tag(name:"solution", value:"Update to version 1.1.16.1 or later.");

  script_tag(name:"impact", value:"Remote exploitation could allow execution of arbitrary code
  to cause head-based buffer overflow via a specially crafted RealAudio or Matroska file.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

xineVer = ssh_cmd(socket:sock, cmd:"xine-config --version");
ssh_close_connection();
if(!xineVer) exit(0);

if(egrep(pattern:"^(0\..*|1\.(0\..*|1(\.0?[0-9]|\.1[0-5])?))([^.0-9]|$)", string:xineVer)){
  report = report_fixed_ver(installed_version:xineVer, fixed_version:"1.1.16.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);