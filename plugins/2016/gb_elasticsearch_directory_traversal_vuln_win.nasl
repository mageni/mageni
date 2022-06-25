###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_directory_traversal_vuln_win.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Elasticsearch < 1.6.1 Multiple Vulnerabilities (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:elasticsearch:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808091");
  script_version("$Revision: 12363 $");
  script_cve_id("CVE-2015-5531", "CVE-2015-5377");
  script_bugtraq_id(75935);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-23 16:03:36 +0530 (Thu, 23 Jun 2016)");
  script_name("Elasticsearch < 1.6.1 Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is running Elasticsearch
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to:

  - an error in the snapshot API calls (CVE-2015-5531)

  - an attack that can result in remote code execution (CVE-2015-5377).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute code or read arbitrary files.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Elasticsearch version 1.0.0 through 1.6.0
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch version 1.6.1,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536017/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elasticsearch/installed", "Host/runs_windows");
  script_require_ports("Services/www", 9200);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!esPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

if(version_in_range(version:esVer, test_version:"1.0.0", test_version2:"1.6.0"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.6.1");
  security_message(data:report, port:esPort);
  exit(0);
}
