###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_dos_vuln_june15_win.nasl 11422 2018-09-17 07:30:48Z mmartin $
#
# PuTTY Denial Of Service Vulnerability June15 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805705");
  script_version("$Revision: 11422 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 09:30:48 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-19 15:32:15 +0530 (Fri, 19 Jun 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("PuTTY Denial Of Service Vulnerability June15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with PuTTY and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to ssh dh group exchange
  does not verify user reply.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"PuTTY version 0.64 on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37291/");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!puttyVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:puttyVer, test_version:"0.64"))
{
  report = report_fixed_ver(installed_version:puttyVer, fixed_version:"WillNotFix");
  security_message(data:report);
  exit(0);
}
