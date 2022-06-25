###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ffmpeg_mult_vuln_lin.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# FFmpeg Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800468");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4631", "CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634",
                "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4637", "CVE-2009-4638",
                "CVE-2009-4639", "CVE-2009-4640");
  script_name("FFmpeg multiple vulnerabilities (Linux)");

  script_xref(name:"URL", value:"https://roundup.ffmpeg.org/roundup/ffmpeg/issue1240");
  script_xref(name:"URL", value:"http://scarybeastsecurity.blogspot.com/2009/09/patching-ffmpeg-into-shape.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition(application
  crash or infinite loop) or possibly allow execution of arbitrary code.");

  script_tag(name:"affected", value:"FFmpeg version 0.5 on Linux.");

  script_tag(name:"insight", value:"The multiple flaws are due to:

  - An out-of-bounds array index error in 'vorbis_dec.c'

  - An off-by-one indexing error in 'vp3.c'

  - Pointer arithmetic error in 'oggparsevorbis.c'

  - Assignment vs comparison operator mix-up error in 'vorbis_dec.c'

  - Integer underflow error leading to stack pointer wrap-around in 'vorbis_dec.c'

  - Integer underflow error in 'mov.c'

  - Type confusion error in 'mov.c'/'utils.c'");

  script_tag(name:"summary", value:"This host is installed with FFmpeg and is prone to multiple
  vulnerabilities");

  script_tag(name:"solution", value:"Upgrad to FFmpeg version 0.5.2 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffmpegVer = get_kb_item("FFmpeg/Linux/Ver");
if(!ffmpegVer){
  exit(0);
}

if(version_is_equal(version:ffmpegVer, test_version:"0.5")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
