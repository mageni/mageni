###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ambari_information_disclosure_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Apache Ambari Information Disclosure Vulnerability
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

CPE = "cpe:/a:apache:ambari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808650");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2016-0707", "CVE-2015-5210");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-09 18:48:58 +0530 (Tue, 09 Aug 2016)");
  script_name("Apache Ambari Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Ambari
  and is prone to information disclosure and open redirection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - Weak permissions used for the '/var/lib/ambari-agent/data' and
    '/var/lib/ambari-agent/keys' directories by the agent.

  - An insufficient validation of user supplied input via 'targetURI'
    parameter in redirect and forward requests.");

  script_tag(name:"impact", value:"Success exploitation will allow local users to
  obtain sensitive information by reading files in the directories and to redirect
  users to arbitrary web sites and conduct phishing attacks.");

  script_tag(name:"affected", value:"Apache Ambari version 1.7 to 2.1.1");

  script_tag(name:"solution", value:"Upgrade to Apache Ambari version 2.1.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");
  script_xref(name:"URL", value:"https://ambari.apache.org/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!amb_Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!amb_Ver = get_app_version(cpe:CPE, port:amb_Port)){
  exit(0);
}

if(version_in_range(version:amb_Ver, test_version:"1.7", test_version2:"2.1.1"))
{
  report =  report_fixed_ver(installed_version:amb_Ver, fixed_version:"2.1.2");
  security_message(data:report, port:amb_Port);
  exit(0);
}
