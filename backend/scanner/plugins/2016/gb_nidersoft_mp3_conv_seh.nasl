###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nidersoft_mp3_conv_seh.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Nidesoft MP3 Converter SEH Local Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:Nidesoft:mp3_converter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107108");
  script_version("$Revision: 11961 $");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-19 11:19:11 +0530 (Mon, 19 Dec 2016)");

  script_name("Nidesoft MP3 Converter SEH Local Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Nidesoft MP3 Converter and is prone to SEH Local Buffer Overflow.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute arbitrary
  code on the system .");
  script_tag(name:"affected", value:"Nidesoft MP3 Converter 2.6.18 on Windows.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40917/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_nidesoft_mp3_conv_detect_win.nasl");
  script_mandatory_keys("Nidesoft/Mp3converter/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cvVer = get_app_version(cpe:CPE)){
  exit(0);
}

if (version_is_equal(version: cvVer, test_version:"2.6.18"))
{
   report = report_fixed_ver(installed_version:cvVer, fixed_version:"None Available");
   security_message(data:report);
   exit(0);
}


