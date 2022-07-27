###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_connect_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Connect Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805662");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-0344", "CVE-2015-0343");
  script_bugtraq_id(75188, 75153);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-19 12:17:48 +0530 (Fri, 19 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to multiple cross site
  scripting vulnerabilities in the web app in Adobe Connect");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary html or script code via the query parameter
  and some unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.4");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jun/61");
  script_xref(name:"URL", value:"https://helpx.adobe.com/adobe-connect/release-note/connect-94-release-notes.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

if(version_is_less(version:acVer, test_version:"9.4"))
{
  report = 'Installed Version: ' + acVer + '\n' +
           'Fixed Version:     ' + "9.4" + '\n';
  security_message(data:report, port:acPort);
  exit(0);
}
