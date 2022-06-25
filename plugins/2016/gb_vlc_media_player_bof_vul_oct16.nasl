###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_bof_vul_oct16.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# VLC Media Player Buffer Overflow Vulnerability Oct16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807370");
  script_version("$Revision: 12096 $");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-03 19:17:45 +0530 (Mon, 03 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Buffer Overflow Vulnerability Oct16");

  script_tag(name:"summary", value:"The host is installed with VLC media player
  and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input while opening a file in player.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to cause denial of service condition.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.2.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.2.4.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40439");
  script_xref(name:"URL", value:"https://www.videolan.org/security/sa1601.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_xref(name:"URL", value:"http://www.videolan.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.2.4"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.4");
  security_message(data:report);
  exit(0);
}
