###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_me_supportcenter_mult_vuln_june15.nasl 50139 2015-06-25 12:19:55Z june$
#
# ManageEngine SupportCenter Plus Multiple Vulnerabilities - June15
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:manageengine:supportcenter_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805807");
  script_version("$Revision: 11452 $");
  script_cve_id("CVE-2015-5149", "CVE-2015-5150");
  script_bugtraq_id(75512, 75506);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-06-25 12:35:38 +0530 (Thu, 25 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine SupportCenter Plus Multiple Vulnerabilities - June15");

  script_tag(name:"summary", value:"The host is running ManageEngine
  SupportCenter Plus and prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Missing user access control mechanisms.

  - 'module' parameter to /workorder/Attachment.jsp?component=Request is not
    properly sanitized to check '../' characters.

  - 'query' and 'compAcct' parameters are not properly sanitized before passing
    to /jsp/ResetADPwd.jsp and jsp/CacheScreenWidth.jsp scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to inject HTML or script code, upload arbitrary files and bypass
  access restrictions.");

  script_tag(name:"affected", value:"ManageEngine SupportCenter Plus version 7.90");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535796/30/0/threaded");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/download_content.php?id=1501");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_supportcenter_detect.nasl");
  script_mandatory_keys("ManageEngine/SupportCenter/Plus/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

## version 7.90 == 7900
if(version_is_equal(version:appVer, test_version:"7900"))
{
  report = 'Installed version: ' + appVer + '\n' +
           'Fixed version:     WillNotFix'  + '\n';
  security_message(data:report, port:appPort);
  exit(0);
}
