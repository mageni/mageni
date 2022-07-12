###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sepm_dos_vuln_feb15.nasl 11614 2018-09-26 07:39:28Z asteins $
#
# Symantec Endpoint Protection 'ccSvcHst.exe' File Denial of Service Vulnerability Feb15
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

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807056");
  script_version("$Revision: 11614 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-26 09:39:28 +0200 (Wed, 26 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:27 +0530 (Tue, 01 Mar 2016)");
  script_name("Symantec Endpoint Protection 'ccSvcHst.exe' File Denial of Service Vulnerability Feb15");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection Manager and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient
  validation of input in an unknown function of the file
  'Smc.exe/SmcGui.exe/ccSvcHst.exe'.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause denial of service conditions.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection version
  12.1.4013");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135185");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535958");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sepVer = get_app_version(cpe:CPE)){
    exit(0);
}

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## https://support.symantec.com/en_US/article.TECH154475.html
if(isnull(sepType) && sepVer =~ "^(12\.1)")
{
  if(version_is_equal(version:sepVer, test_version:"12.1.4013.4013"))
  {
    report = report_fixed_ver(installed_version:sepVer, fixed_version:"WillNotFix");
    security_message(data:report);
    exit(0);
  }
}

exit(99);