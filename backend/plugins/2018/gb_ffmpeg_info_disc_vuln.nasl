###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ffmpeg_info_disc_vuln.nasl 8646 2018-02-02 16:20:32Z cfischer $
#
# FFmpeg Information Disclosure Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112190");
  script_version("$Revision: 8646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-02 17:20:32 +0100 (Fri, 02 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 16:35:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-1208");

  script_name("FFmpeg Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"Integer underflow in the mov_read_default function in libavformat/mov.c in FFmpeg
allows remote attackers to obtain sensitive information from heap and/or stack memory via a crafted MP4 file.");
  script_tag(name:"vuldetect", value:"Checks the version.");
  script_tag(name:"affected", value:"FFmpeg before version 2.4.6.");
  script_tag(name:"solution", value:"Upgrade to version 2.4.6 or later");

  script_xref(name:"URL", value:"https://github.com/FFmpeg/FFmpeg/blob/n2.4.6/Changelog");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/chromium/issues/detail?id=444546");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe:CPE)) exit(0);

if (version_is_less(version:version, test_version:"2.4.6")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.4.6");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
