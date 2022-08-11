###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gom_player_dos_vuln_feb14_win.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# GOM Media Player Denial of Service (dos) Vulnerability Feb14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:gomlab:gom_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804304");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-7184");
  script_bugtraq_id(64481);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-03 11:14:36 +0530 (Mon, 03 Feb 2014)");
  script_name("GOM Media Player Denial of Service (dos) Vulnerability Feb14 (Windows)");


  script_tag(name:"summary", value:"The host is installed with GOM Media Player and is prone to
denial-of-service vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is in the application caused by improper bounds checking when
processing .avi files with an overly long string.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory and
cause a denial of service or execute an arbitrary code.");
  script_tag(name:"affected", value:"GOM Media Player version 2.2.56.5158 and prior on Windows");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89914");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/30414");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_mandatory_keys("GOM/Player/Ver/Win");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!gomVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:gomVer, test_version:"2.2.56.5158"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
