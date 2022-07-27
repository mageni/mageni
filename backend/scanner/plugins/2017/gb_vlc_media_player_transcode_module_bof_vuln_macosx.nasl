###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_transcode_module_bof_vuln_macosx.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# VLC Media Player 'audio.c' Heap-Based Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810722");
  script_version("$Revision: 11936 $");
  script_cve_id("CVE-2014-6440");
  script_bugtraq_id(72950);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-30 15:38:41 +0530 (Thu, 30 Mar 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player 'audio.c' Heap-Based Buffer Overflow Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in the transcode
  module that may allow a corrupted stream to overflow buffers on the heap.
  With a non-malicious input, this could lead to heap corruption and a crash.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (crash) and possibly execute arbitrary
  code.");

  script_tag(name:"affected", value:"VideoLAN VLC media player before 2.1.5 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to VideoLAN VLC media player version
  2.1.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q1/751");
  script_xref(name:"URL", value:"http://billblough.net/blog/2015/03/04/cve-2014-6440-heap-overflow-in-vlc-transcode-module");
  script_xref(name:"URL", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_xref(name:"URL", value:"http://www.videolan.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.1.5"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.1.5");
  security_message(data:report);
  exit(0);
}
