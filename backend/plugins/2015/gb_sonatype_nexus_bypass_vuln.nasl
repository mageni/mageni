###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonatype_nexus_bypass_vuln.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Sonatype Nexus OSS/Pro Security Bypass Vulnerability
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

CPE = "cpe:/a:sonatype:nexus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805330");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2014-2034");
  script_bugtraq_id(65956);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-01-27 13:00:12 +0530 (Tue, 27 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Nexus OSS/Pro
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain unspecified input is not properly
  verified before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions.");

  script_tag(name:"affected", value:"Nexus OSS/Pro versions 2.4.0 through 2.7.1.");

  script_tag(name:"solution", value:"Upgrade to Nexus OSS/Pro version 2.7.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57142");
  script_xref(name:"URL", value:"http://www.sonatype.org/advisories/archive/2014-03-03-Nexus");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sonatype_nexus_detect.nasl");
  script_mandatory_keys("nexus/installed");
  script_require_ports("Services/www", 8081);
  script_xref(name:"URL", value:"http://www.sonatype.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!nexusVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_in_range(version:nexusVer, test_version:"2.4.0", test_version2:"2.7.1"))
{
  report = 'Installed version: ' + nexusVer + '\n' +
           'Fixed version: 2.7.2\n';

  security_message(port:http_port, data:report);
  exit(0);
}
