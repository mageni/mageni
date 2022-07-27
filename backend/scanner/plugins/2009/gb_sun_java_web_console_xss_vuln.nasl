###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_console_xss_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# Sun Java Web Console Multiple XSS Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800826");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2283");
  script_name("Sun Java Web Console Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35597");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1712");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-136987-03-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-262428-1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sun_java_web_console_detect.nasl");
  script_mandatory_keys("Sun/JavaWebConsole/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Sun Java Web Console version 3.0.2 to 3.0.5.");

  script_tag(name:"insight", value:"Errors in help jsp script that is not properly sanitising input data before
  being returned to the user, which can be exploited to cause web script or HTML code injection.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"summary", value:"The host is running Java Web Console and is prone to Multiple
  Cross-Site Scripting Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jwcPort = 6789;
jwcVer = get_kb_item("Sun/JavaWebConsole/Ver");
if(!jwcVer)
  exit(0);

if(version_in_range(version:jwcVer, test_version:"3.0.2", test_version2:"3.0.5")) {
  report = report_fixed_ver(installed_version:jwcVer, fixed_version:"See references");
  security_message(port:jwcPort, data:report);
  exit(0);
}

exit(99);