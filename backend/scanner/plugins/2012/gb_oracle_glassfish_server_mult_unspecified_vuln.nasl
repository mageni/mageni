###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_server_mult_unspecified_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Oracle GlassFish Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:oracle:glassfish_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802417");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2012-0081", "CVE-2011-3564", "CVE-2012-0104");
  script_bugtraq_id(51484, 51485, 51497);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-01-23 13:43:23 +0530 (Mon, 23 Jan 2012)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Multiple Unspecified Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47603/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026537");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to affect confidentiality,
integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 2.1.1, 3.1.1 and 3.0.1");

  script_tag(name:"insight", value:"Multiple unspecified flaws are exists in the application related to
Administration and Web Container, which allows attackers to affect confidentiality, integrity and availability via
unknown vectors.");

  script_tag(name:"summary", value:"The host is running GlassFish Server and is prone to multiple unspecified
vulnerabilities.");

  script_tag(name:"solution", value:"Apply the security updates from the referenced vendor advisory.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version:"2.1.1") ||
    version_is_equal(version: version, test_version:"3.0.1") ||
    version_is_equal(version: version, test_version:"3.1.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
