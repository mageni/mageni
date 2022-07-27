###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_two_factor_auth_bypass_vuln_nov17.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Joomla! Core Two-factor Authentication Bypass Vulnerability Nov17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811897");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-16634");
  script_bugtraq_id(101701);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-08 10:36:51 +0530 (Wed, 08 Nov 2017)");
  script_name("Joomla! Core Two-factor Authentication Bypass Vulnerability Nov17");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error related to
  2-factor-authentication method.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to bypass certain security restrictions and perform unauthorized
  actions, this may aid in launching further attacks.");

  script_tag(name:"affected", value:"Joomla core version 3.2.0 through 3.8.1");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/713-20171102-core-2-factor-authentication-bypass.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.joomla.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!jVer = get_app_version(cpe:CPE, port:jPort)){
  exit(0);
}

if(jVer =~ "^(3\.)")
{
  if(version_in_range(version:jVer, test_version:"3.2.0", test_version2:"3.8.1"))
  {
    report = report_fixed_ver( installed_version:jVer, fixed_version:"3.8.2");
    security_message( data:report, port:jPort);
    exit(0);
  }
}
exit(0);