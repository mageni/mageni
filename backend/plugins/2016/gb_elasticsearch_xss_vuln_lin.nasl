###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_xss_vuln_lin.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Elasticsearch Cross-site Scripting (XSS) Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808506");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2014-6439");
  script_bugtraq_id(70233);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 18:37:05 +0530 (Tue, 28 Jun 2016)");
  script_name("Elasticsearch Cross-site Scripting (XSS) Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Elasticsearch
  and is prone to Cross-site Scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to an error in the
  CORS functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elasticsearch version 1.3.x and prior
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch version 1.4.0.Beta1,
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533602/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elasticsearch/installed", "Host/runs_unixoide");
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

esVer1 = eregmatch(pattern:"([0-9.]+)", string:esVer);
esVer = esVer1[1];

##version info taken from https://www.elastic.co/downloads/past-releases
if(version_is_less(version:esVer, test_version:"1.4.0"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.4.0.Beta1");
  security_message(data:report, port:esPort);
  exit(0);
}

