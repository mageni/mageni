###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winamp_mult_bof_sep14_win_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Winamp Libraries Multiple Buffer Overflow Vulnerability - Sep14
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

CPE = "cpe:/a:nullsoft:winamp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804845");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-4694");
  script_bugtraq_id(60883);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-09-18 16:49:22 +0530 (Thu, 18 Sep 2014)");

  script_name("Winamp Libraries Multiple Buffer Overflow Vulnerability - Sep14");

  script_tag(name:"summary", value:"This host is installed with Winamp and
  is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exist as user-supplied input is not
  properly validated when handling a specially crafted overly long Skins directory
  name.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or potentially allowing the execution
  of arbitrary code.");

  script_tag(name:"affected", value:"Winamp prior version 5.64 Build 3418");

  script_tag(name:"solution", value:"Upgrade to Winamp version 5.64 Build 3418
  or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/85399");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?t=364291");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:version, test_version:"5.6.4.3418"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
