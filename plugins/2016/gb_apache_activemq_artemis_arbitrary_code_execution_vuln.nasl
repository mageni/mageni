###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_artemis_arbitrary_code_execution_vuln.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Apache ActiveMQ Artemis Arbitrary Code Execution Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:apache:activemq_artemis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809342");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-4978");
  script_bugtraq_id(93142);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 13:13:58 +0530 (Thu, 06 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache ActiveMQ Artemis Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ Artemis
  and is prone to arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a class implementing the
  Serializable interface is free to implement the
  'readObject(java.io.ObjectInputStreamin)' method however it chooses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to replace web application files with malicious code and perform
  remote code execution on the system.");

  script_tag(name:"affected", value:"Apache ActiveMQ Artemis Version before 1.4.0");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Artemis Version
  1.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities.pdf");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_artemis_detect.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("ActiveMQ/Artemis/installed");
  script_xref(name:"URL", value:"http://activemq.apache.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(version_is_less(version:appVer, test_version:"1.4.0"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"1.4.0");
  security_message(data:report, port:appPort);
  exit(0);
}
