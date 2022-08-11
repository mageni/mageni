###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_open_redirect_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Joomla! Open Redirect Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112051");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2015-5608");
  script_bugtraq_id(76496);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-21 10:36:22 +0200 (Thu, 21 Sep 2017)");
  script_name("Joomla! Open Redirect Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla is prone to the following open redirect vulnerability:

  - Inadequate checking of the return value allowed to redirect to an external page.");

  script_tag(name:"affected", value:"Joomla! versions 3.0.0 through 3.4.1");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/617-20150601-core-open-redirect.html");

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

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_in_range(version:ver, test_version:"3.0.0", test_version2:"3.4.1"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.4.2");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
