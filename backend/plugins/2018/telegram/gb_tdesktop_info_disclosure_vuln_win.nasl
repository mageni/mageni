###############################################################################
# OpenVAS Vulnerability Test
#
# Telegram Desktop Information Disclosure Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:telegram:tdesktop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814310");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-17780");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-09 17:30:33 +0530 (Fri, 09 Nov 2018)");
  script_name("Telegram Desktop Information Disclosure Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Telegram Desktop
  and is prone to information disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the peer-to-peer
  connection is not private by design, as it directly exposes the IP addresses
  of the two participants. A mechanism to mask users IP addresses when calling
  each other is not present on Telegram's desktop client");

  script_tag(name:"impact", value:"Successful exploitation will expose a user's
  IP address when making a call.");

  script_tag(name:"affected", value:"Telegram Desktop version 1.3.14.0 on Windows");

  script_tag(name:"solution", value:"Upgrade to the version 1.3.17.0 beta
  or 1.4.0.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.inputzero.io/2018/09/bug-bounty-telegram-cve-2018-17780.html");
  script_xref(name:"URL", value:"https://desktop.telegram.org/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_telegram_desktop_detect_win.nasl");
  script_mandatory_keys("Telegram/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
telVer = infos['version'];
telPath = infos['location'];

if(version_is_equal(version:telVer, test_version:"1.3.14.0"))
{
  report = report_fixed_ver(installed_version:telVer, fixed_version:"1.4.0.0 and 1.3.17.0 beta", install_path:telPath);
  security_message(data:report);
  exit(0);
}
exit(0);
