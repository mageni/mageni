###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_xi_multiple_vuln_jun16.nasl 12490 2018-11-22 13:45:33Z cfischer $
#
# Nagios XI Multiple Vulnerabilities - June16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:nagios:nagiosxi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807835");
  script_version("$Revision: 12490 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 14:45:33 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-08 16:38:53 +0530 (Wed, 08 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Nagios XI Multiple Vulnerabilities - June16");

  script_tag(name:"summary", value:"This host is running Nagios XI and is
  prone to multiple vulnerabilities.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.105749.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple errors are due to,

  - Insufficient sanitization of input passed via 'host' and 'service'
    GET parameters in the 'nagiosim.php' page.

  - Unescaped user input being passed to shell functions as an argument.

  - An insecure implementation of the application's component upload functionality.

  - An insecure implementation of the password reset functionality.

  - Multiple server-side request forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct command injection, gain elevated privileges, conduct
  server side request forgery attacks, conduct account hijacking and inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Nagios XI version 5.2.7 and prior.");

  script_tag(name:"solution", value:"Upgrade to Nagios XI version 5.2.8.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-xi");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39899");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137293");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/9");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/NagiosXI-Advisory.pdf");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in gb_nagios_xi_multiple_vulnerabilities_06_16.nasl (OID:1.3.6.1.4.1.25623.1.0.105749)