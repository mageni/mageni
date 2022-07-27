###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_kibana_ssl_dos_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Elasticsearch Kibana 'SSL Client Access' DoS Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:elasticsearch:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811406");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-8452");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-03 20:01:42 +0530 (Mon, 03 Jul 2017)");
  script_name("Elasticsearch Kibana 'SSL Client Access' DoS Vulnerability");

  script_tag(name:"summary", value:"This host is running Elasticsearch Kibana
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to Kibana is configured for SSL
  client access, file descriptors will fail to be cleaned up after certain requests
  and will accumulate over time until the process crashes. Requests that are
  canceled before data is sent can also crash the process.");

  script_tag(name:"impact", value:"Successful exploitation will lead to denial of
  service condition.");

  script_tag(name:"affected", value:"Elasticsearch Kibana version 5.x prior to
  5.2.1.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch Kibana version
  5.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elasticsearch_kibana_detect.nasl");
  script_mandatory_keys("Elasticsearch/Kibana/Installed");
  script_require_ports("Services/www", 5601);
  script_xref(name:"URL", value:"https://www.elastic.co");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!kibanaPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!kibanaVer = get_app_version(cpe:CPE, port:kibanaPort)){
 exit(0);
}

if(version_in_range(version:kibanaVer, test_version:"5.0", test_version2:"5.2.0"))
{
  report = report_fixed_ver(installed_version:kibanaVer, fixed_version:"5.2.1");
  security_message(data:report, port:kibanaPort);
  exit(0);
}
