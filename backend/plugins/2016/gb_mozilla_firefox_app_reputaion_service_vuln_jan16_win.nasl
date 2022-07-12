###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_app_reputaion_service_vuln_jan16_win.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Mozilla Firefox Application Reputation Service Vulnerability - Jan16 (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807051");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-1947");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-29 09:21:18 +0530 (Fri, 29 Jan 2016)");
  script_name("Mozilla Firefox Application Reputation Service Vulnerability - Jan16 (Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to application reputation service disabling
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to disabling of
  Application Reputation service that leads to removal of the ability of Safe
  browsing to warn against potentially malicious downloads.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to do potentially malicious downloads.");

  script_tag(name:"affected", value:"Mozilla Firefox versions 43.x on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 44
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories");
  script_xref(name:"URL", value:"http://msisac.cisecurity.org/advisories/2016/2016-018.cfm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(ffVer =~ "^43")
{
  if(version_is_less(version:ffVer, test_version:"44.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, fixed_version:"44.0");
    security_message(data:report);
    exit(0);
  }
}
